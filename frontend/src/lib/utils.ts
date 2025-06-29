import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const getAuthToken = () => {
  return localStorage.getItem("accessToken");
};

export const getRefreshToken = () => {
  return localStorage.getItem("refreshToken");
};

export const setAuthToken = (token: string) => {
  localStorage.setItem("accessToken", token);
};

export const clearAuthTokens = () => {
  localStorage.removeItem("accessToken");
  localStorage.removeItem("refreshToken");
};

export const isUserAuthenticated = () => {
  return !!getAuthToken();
};
