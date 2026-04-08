import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import * as authController from '../controllers/authController';

const router = Router();

// Basic rate limiter for auth endpoints to mitigate brute-force attacks
const authLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 20, // limit each IP to 20 requests per windowMs
	standardHeaders: true,
	legacyHeaders: false,
});

router.post('/register', authLimiter, authController.register);
router.post('/login', authLimiter, authController.login);
router.post('/login-viewer', authLimiter, authController.loginViewer);
router.post('/refresh', authController.refresh);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);
router.get('/verify-email', authController.verifyEmail);
router.post('/verify-email', authController.verifyEmailPost);
router.post('/resend-verification', authController.resendVerification);
router.post('/logout', authController.logout);

export default router;
