import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },

    provider: {
      type: String,
      enum: ["local", "google", "github"],
      default: "local",
    },

    isEmailVerified: { type: Boolean, default: false },

    refreshToken: { type: String },

    // For forgot password functionality
    forgotPasswordToken: { type: String },
    forgotPasswordExpiry: { type: Date },

    // For email verification functionality
    emailVerificationToken: { type: String },
    emailVerificationExpiry: { type: Date },
  },
  { timestamps: true }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Compare input password with DB hash
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Generate Access Token
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    { _id: this._id, email: this.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );
};

// Generate Refresh Token
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    { _id: this._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );
};

// Generate Password Reset Token
userSchema.methods.generatePasswordResetToken = function () {
  const unHashedToken = crypto.randomBytes(20).toString("hex");
  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

  this.forgotPasswordToken = hashedToken;
  this.forgotPasswordExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes
  return unHashedToken;
};

// Generate Email Verification Token
userSchema.methods.generateEmailVerificationToken = function () {
  const unHashedToken = crypto.randomBytes(20).toString("hex");
  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

  this.emailVerificationToken = hashedToken;
  this.emailVerificationExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
  return unHashedToken;
};

export const User = mongoose.model("User", userSchema);
