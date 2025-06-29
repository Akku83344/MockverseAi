import apiClient from "@/lib/axios";
import axios from "axios";

// This axios instance is for endpoints that don't need authentication
// Like login, register, etc.
const authAPI = axios.create({
  baseURL: `${import.meta.env.VITE_API_URL}/api/v1/user`,
  withCredentials: true,
});

interface ILogin {
  email: string;
  password: string;
}

interface IRegister extends ILogin {
  username: string;
}

interface IForgotPassword {
  email: string;
}

export interface IChangeAvatar {
  avatar: File;
}

interface IResetPassword {
  newPassword: string;
}

interface IRefreshToken {
  refreshToken: string;
}

const UserService = {
  login: (payload: ILogin) => {
    return authAPI.post("/login", payload);
  },

  refreshToken: (payload: IRefreshToken) => {
    return authAPI.post("/refresh-token", payload);
  },

  googleLogin: () => {
    return authAPI.get("/google");
  },

  githubLogin: () => {
    return authAPI.get("/github");
  },

  register: (payload: IRegister) => {
    return authAPI.post("/register", payload);
  },

  forgotPassword: (payload: IForgotPassword) => {
    return authAPI.post("/forgot-password", payload);
  },

  resetPassword: (payload: IResetPassword, token: string) => {
    return authAPI.post(`/reset-password/${token}`, payload);
  },

  resendVerificationEmail: (userId: string) => {
    return authAPI.post(`/resend-email-verification/${userId}`);
  },

  verifyEmail: (verificationToken: string) => {
    return authAPI.get(`/verify-email/${verificationToken}`);
  },

  logout: () => {
    return apiClient.post("/api/v1/user/logout");
  },

};

export default UserService;