import express from "express";
import {
  forgotPassword,
  handleSocialLogin,
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


// SSO routes
router.route("/google").get(
  passport.authenticate("google", {
    scope: ["profile", "email"],
  }),
  (req, res) => {
    res.send("redirecting to google...");
  }
);

router.route("/github").get(
  passport.authenticate("github", {
    scope: ["profile", "email"],
  }),
  (req, res) => {
    res.send("redirecting to github...");
  }
);

router
  .route("/google/callback")
  .get(passport.authenticate("google"), handleSocialLogin);

router
  .route("/github/callback")
  .get(passport.authenticate("github"), handleSocialLogin);

export default router;
