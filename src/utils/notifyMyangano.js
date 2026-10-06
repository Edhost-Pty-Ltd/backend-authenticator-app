import { config } from '../config.js';

export async function notifyMyangano2FAChange(authServiceUserId, enabled) {
  const url = config.myanganoWebhookUrl;
  if (!url) return;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.myanganoServiceApiKey}`,
      },
      body: JSON.stringify({ authServiceUserId, enabled }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`Webhook responded ${response.status}`);
  } finally {
    clearTimeout(timeout);
  }
}
