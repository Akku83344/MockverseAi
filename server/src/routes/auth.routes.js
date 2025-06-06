import express from "express";
import { forgotPassword, loginUser, logoutUser, refreshToken, registerUser, resetPassword } from "../controllers/auth.controller.js";

const router = express.Router();

// Route → POST /api/auth/register
router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/refresh-token", refreshToken);
router.post("/logout", logoutUser);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

export default router;