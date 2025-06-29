import { clearAuthTokens, getAuthToken, getRefreshToken, setAuthToken } from "@/lib/utils";
import axios, { AxiosError } from "axios";
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import UserService from "@/services/userService";
import { toast } from "sonner";

const apiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

apiClient.interceptors.request.use(
  (config) => {
    const authToken = getAuthToken();
    if (authToken) {
      config.headers.Authorization = authToken;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

let isRefreshing = false;

let failedQueue: { resolve: (value: unknown) => void; reject: (reason?: any) => void }[] = [];

const processQueue = (error: AxiosError | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });

  failedQueue = [];
};

apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    // Return if not 401 error or if already retrying or if no original request
    if (!error.response || error.response.status !== 401 || originalRequest._retry || !originalRequest) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      })
        .then(() => {
          return apiClient(originalRequest);
        })
        .catch((err) => {
          return Promise.reject(err);
        });
    }

    isRefreshing = true;

    try {
      const refreshToken = getRefreshToken();

      if (!refreshToken) {
        clearAuthTokens();
        processQueue(error);
        return Promise.reject(error);
      }

      const response = await UserService.refreshToken({ refreshToken });
      const { accessToken: newAccessToken } = response.data.data;

      if (newAccessToken) {
        setAuthToken(newAccessToken);
        processQueue(null, newAccessToken);

        if (originalRequest.headers) {
          originalRequest.headers.Authorization = newAccessToken;
        }
        return apiClient(originalRequest);
      } else {
        clearAuthTokens();
        processQueue(error);
        window.location.href = "/login";
        return Promise.reject(error);
      }
    } catch (refreshError) {
      clearAuthTokens();
      processQueue(error);
      window.location.href = "/login";
      toast.error("Session expired. Please login again.");
      return Promise.reject(refreshError);
    } finally {
      isRefreshing = false;
    }
  }
);

export default apiClient;