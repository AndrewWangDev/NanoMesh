export async function verifyTurnstile(
  token: string,
  secretKey: string,
  remoteip?: string | null
): Promise<boolean> {
  try {
    const formData = new FormData();
    formData.append("secret", secretKey);
    formData.append("response", token);
    if (remoteip && remoteip.trim()) {
      formData.append("remoteip", remoteip.trim());
    }

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData
    });

    const data: any = await res.json();
    return data.success === true;
  } catch (e) {
    return false;
  }
}
