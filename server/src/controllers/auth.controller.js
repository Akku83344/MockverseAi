// controllers/auth.controller.js
import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken"
import { sendEmail } from "../utils/sendEmail.js";

export const registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

   
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already in use." });
    }

    const newUser = await User.create({ username, email, password });

    const emailToken = newUser.generateEmailVerificationToken();

    
    await newUser.save({ validateBeforeSave: false });

    // Create verification URL
    const verifyURL = `${process.env.CLIENT_URL}/verify-email/${emailToken}`;

    // Send verification email
    await sendEmail({
      email: newUser.email,
      subject: "Verify Your Email",
      username: newUser.username,
      buttonText: "Verify Email",
      buttonLink: verifyURL,
      intro: "Thanks for registering. Please verify your email address.",
      outro: "If you didn’t request this, please ignore this email.",
    });

    // Send success response
    res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",
      user: {
        _id: newUser._id,
        username: newUser.username,
        email: newUser.email,
      },
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ message: "Server error." });
  }
};
export const verifyEmail = async (req, res) => {
  const { token } = req.params;

  if (!token) {
    return res.status(400).json({ message: "Invalid or missing token." });
  }

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    verifyEmailToken: hashedToken,
    verifyEmailExpiry: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({ message: "Token is invalid or has expired." });
  }

  user.isEmailVerified = true;
  user.verifyEmailToken = undefined;
  user.verifyEmailExpiry = undefined;

  await user.save({ validateBeforeSave: false });

  res.status(200).json({ message: "Email verified successfully. You can now log in." });
};

export const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // 1. Check for email and password
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  // 2. Find user
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "Invalid email or password." });
  }

  // 3. Check password
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  // 4. Check if email is verified
  if (!user.isEmailVerified) {
    return res.status(401).json({ message: "Please verify your email to login." });
  }

  // 5. Generate tokens
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  // 6. Store refreshToken in DB
  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  // 7. Set refreshToken as httpOnly cookie
  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })
    .status(200)
    .json({
      message: "Login successful",
      accessToken,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
      },
    });
});

export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ message: "Refresh token not found" });

    // Verify token
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded._id);
    if (!user || user.refreshToken !== token)
      return res.status(403).json({ message: "Invalid refresh token" });

    // Generate new tokens
    const newAccessToken = user.generateAccessToken();
    const newRefreshToken = user.generateRefreshToken();

    user.refreshToken = newRefreshToken;
    await user.save();

    // Send new tokens
    res
      .cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      })
      .json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ message: "Token expired or invalid" });
  }
};

export const logoutUser = async (req, res) => {
  try {
    // Clear the refresh token cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
    });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    return res.status(500).json({ message: "Logout failed", error });
  }
};


export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });

  const resetToken = user.generatePasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

  try {
    await sendEmail({
      email: user.email,
      subject: "Reset Your Password",
      username: user.username,
      buttonText: "Reset Password",
      buttonLink: resetURL,
      intro: "You have requested to reset your password.",
      outro: "If you didn’t request this, please ignore.",
    });

    res.status(200).json({ message: "Reset email sent successfully" });
  } catch (error) {
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(500).json({ message: "Failed to send email", error: error.message });
  }
};


export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      forgotPasswordToken: hashedToken,
      forgotPasswordExpiry: { $gt: Date.now() }, // check expiry
    });

    if (!user) {
      return res.status(400).json({ message: "Token is invalid or expired" });
    }

    user.password = password;
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;

    await user.save();

    res.status(200).json({ message: "Password reset successful. You can now log in." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

export const handleSocialLogin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user?._id);

    if (!user) {
      return next(new ApiError(404, "User does not exist"));
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    };

    return res
      .status(301)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .redirect(`${process.env.CLIENT_SSO_REDIRECT_URL}?accessToken=${accessToken}&refreshToken=${refreshToken}`);
  } catch (error) {
    next(error);
  }
};
