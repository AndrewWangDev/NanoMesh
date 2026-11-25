/**
 * Generates AWS SigV4 pre-signed S3 URLs for Cloudflare R2 storage operations.
 */
import { AwsClient } from "aws4fetch";
import { Env } from "../types";

/**
 * Initializes an S3-compatible SigV4 client for Cloudflare R2.
 */
function getClient(env: Env) {
  return new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID || "mock-access-key",
    secretAccessKey: env.R2_SECRET_ACCESS_KEY || "mock-secret-key",
    service: "s3",
    region: "auto"
  });
}

/**
 * Resolves the Cloudflare Account ID from environment bindings.
 */
export function getCloudflareAccountId(env: Env): string {
  return env.Cloudflare_Account_ID || (env as any).CLOUDFLARE_ACCOUNT_ID || "";
}

/**
 * Derives the S3-compatible REST endpoint for the configured R2 bucket.
 */
function getEndpoint(env: Env) {
  const bucket = (env as any).R2_BUCKET_NAME || "nanomesh-assets";
  return `https://${getCloudflareAccountId(env)}.r2.cloudflarestorage.com/${bucket}`;
}

/**
 * Initiates an S3 multipart upload session on Cloudflare R2.
 */
export async function createMultipartUpload(
  env: Env,
  objectKey: string,
  contentType: string = "application/octet-stream"
): Promise<string> {
  const aws = getClient(env);
  const url = `${getEndpoint(env)}/${objectKey}?uploads`;
  const response = await aws.fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": contentType
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to create multipart upload: ${await response.text()}`);
  }

  const text = await response.text();
  const match = text.match(/<UploadId>(.*?)<\/UploadId>/);
  if (!match) throw new Error("UploadId not found in S3 response");
  return match[1];
}

/**
 * Generates an array of pre-signed PUT URLs for S3 multipart upload parts.
 */
export async function getPresignedUrls(
  env: Env,
  objectKey: string,
  uploadId: string,
  partsCount: number,
  expiresInSeconds: number = 300
): Promise<string[]> {
  const aws = getClient(env);
  const endpoint = getEndpoint(env);
  const urls: string[] = [];

  for (let i = 1; i <= partsCount; i++) {
    const url = new URL(`${endpoint}/${objectKey}?partNumber=${i}&uploadId=${uploadId}`);
    url.searchParams.set("X-Amz-Expires", String(expiresInSeconds));
    const request = await aws.sign(url, {
      method: "PUT",
      aws: { signQuery: true }
    });
    urls.push(request.url);
  }
  return urls;
}

/**
 * Completes a multipart upload by assembling uploaded parts with their ETags.
 */
export async function completeMultipartUpload(
  env: Env,
  objectKey: string,
  uploadId: string,
  parts: { PartNumber: number; ETag: string }[]
): Promise<void> {
  const aws = getClient(env);
  const url = `${getEndpoint(env)}/${objectKey}?uploadId=${uploadId}`;

  parts.sort((a, b) => a.PartNumber - b.PartNumber);

  const body = `
    <CompleteMultipartUpload>
      ${parts.map((p) => `<Part><PartNumber>${p.PartNumber}</PartNumber><ETag>${p.ETag}</ETag></Part>`).join("")}
    </CompleteMultipartUpload>
  `;

  const response = await aws.fetch(url, {
    method: "POST",
    body
  });

  if (!response.ok) {
    throw new Error(`Failed to complete multipart upload: ${await response.text()}`);
  }
}

/**
 * Aborts an active S3 multipart upload session and purges incomplete parts.
 */
export async function abortMultipartUpload(
  env: Env,
  objectKey: string,
  uploadId: string
): Promise<void> {
  const aws = getClient(env);
  const url = `${getEndpoint(env)}/${objectKey}?uploadId=${uploadId}`;

  const response = await aws.fetch(url, {
    method: "DELETE"
  });

  if (!response.ok) {
    throw new Error(`Failed to abort multipart upload: ${await response.text()}`);
  }
}

/**
 * Deletes a single object from Cloudflare R2 via S3-compatible REST API.
 */
export async function deleteObject(env: Env, objectKey: string): Promise<void> {
  const aws = getClient(env);
  const url = `${getEndpoint(env)}/${objectKey}`;

  const response = await aws.fetch(url, {
    method: "DELETE"
  });

  if (!response.ok) {
    throw new Error(`Failed to delete object: ${await response.text()}`);
  }
}

/**
 * Generates a single pre-signed PUT URL for direct client-to-R2 single-part uploads.
 */
export async function getSinglePresignedPutUrl(
  env: Env,
  objectKey: string,
  contentType: string = "application/octet-stream",
  contentLength?: number,
  expiresInSeconds: number = 300
): Promise<string> {
  const aws = getClient(env);
  const endpoint = getEndpoint(env);
  const url = new URL(`${endpoint}/${objectKey}`);
  url.searchParams.set("X-Amz-Expires", String(expiresInSeconds));

  const headers: Record<string, string> = {
    "Content-Type": contentType
  };
  if (typeof contentLength === "number" && contentLength >= 1) {
    headers["Content-Length"] = String(Math.floor(contentLength));
  } else {
    throw new Error(
      "Content-Length is required and must be a positive integer >= 1 for presigned PUT"
    );
  }

  const request = await aws.sign(url, {
    method: "PUT",
    headers,
    aws: { signQuery: true, allHeaders: true }
  });
  return request.url;
}
