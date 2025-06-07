import express from "express";
import {
  forgotPassword,
  login,
  logoutUser,
  refreshToken,
  registerUser,
  resetPassword,
  verifyEmail,
} from "../controllers/auth.controller.js";

const router = express.Router();

// Register & Login
router.post("/register", registerUser);
router.post("/login", login);

// Email Verification
router.get("/verify-email/:token", verifyEmail); // ✅ Added

// Token Refresh & Logout
router.get("/refresh-token", refreshToken);
router.post("/logout", logoutUser);

// Password Reset
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

export default router;
