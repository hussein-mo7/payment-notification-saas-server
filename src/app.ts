import './loadEnv';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { getBrevoEmailHealth } from './services/verificationEmail';
import routes from './routes';
import { errorHandler, notFound } from './middleware';

const app = express();

// Security headers
app.use(helmet());

// Restrict CORS to configured frontend/admin origins
const allowedOrigins = [config.urls.frontend, config.urls.admin, 'http://localhost:3000', 'http://127.0.0.1:3000'];
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow non-browser requests (e.g. curl, server-to-server) which have no origin
      if (!origin) return callback(null, true);
      return callback(null, allowedOrigins.includes(origin));
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const emailStatusHandler = (_req: express.Request, res: express.Response): void => {
  const apiPublic = (process.env.API_PUBLIC_URL ?? '').trim();
  const feRaw = (process.env.FRONTEND_URL ?? '').trim();
  let feHint: string | undefined;
  if (feRaw && /\/app\/?$/i.test(feRaw)) {
    feHint =
      'FRONTEND_URL should be the site origin only (no /app). Example: https://your-app.vercel.app — code strips /app if present.';
  }
  const h = getBrevoEmailHealth();
  res.json({
    brevoApiKeySet: h.brevoApiKeySet,
    senderConfigured: h.senderConfigured,
    senderEmail: h.senderEmail,
    problem: h.problem,
    apiPublicUrlSet: apiPublic.length > 0,
    frontendUrlSet: feRaw.length > 0,
    frontendUrlHint: feHint,
    brevoReady: h.ready,
    note: h.ready
      ? 'Verification email is sent via Brevo.'
      : h.problem ?? 'Fix Brevo configuration.',
  });
};

const healthRootHandler = (_req: express.Request, res: express.Response): void => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
};

app.get('/health', healthRootHandler);
app.get('/api/health', healthRootHandler);

app.get('/health/email', emailStatusHandler);
app.get('/api/health/email', emailStatusHandler);

app.use('/api', routes);

app.use(notFound);
app.use(errorHandler);

/** Render free tier idles ~15m after no *external* HTTP; ping a bit under that. Only runs while the process is awake — set KEEP_ALIVE_URL on Render + use UptimeRobot/cron-job.org as backup. */
const KEEP_ALIVE_INTERVAL_MS = 10 * 60 * 1000;
const keepAliveUrl = config.keepAlive.url || `http://127.0.0.1:${config.port}/health`;
const keepAliveIsPublic =
  /^https?:\/\//i.test(keepAliveUrl) && !/^https?:\/\/(127\.0\.0\.1|localhost)/i.test(keepAliveUrl);
if (config.env === 'production' && !keepAliveIsPublic) {
  console.warn(
    '[keep-alive] KEEP_ALIVE_URL is not set to your public HTTPS URL on this host. In-process pings use localhost and do not stop Render from sleeping. Set KEEP_ALIVE_URL=https://<your-app>.onrender.com/health in Render env, and/or use an external ping (UptimeRobot, cron-job.org) every 5–10 min.'
  );
} else {
  console.log(`[keep-alive] GET ${keepAliveUrl} every ${KEEP_ALIVE_INTERVAL_MS / 60000} min`);
}
setInterval(() => {
  void fetch(keepAliveUrl).catch((err) => {
    console.error('Keep-alive ping failed:', err);
  });
}, KEEP_ALIVE_INTERVAL_MS);

export default app;
