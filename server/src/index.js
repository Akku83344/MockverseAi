import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import connectDB from "./config/db.js";
import authRoutes from "./routes/auth.routes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());

// DB connection
connectDB();

// Routes
app.use("/api/auth", authRoutes); 

// Server listen
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
