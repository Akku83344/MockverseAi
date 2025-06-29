import { lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router";
import "./index.css";

// Fullscreen Loader
const FullScreenLoader = lazy(() => import("./components/loaders/FullScreenLoader.tsx"));

// Layouts
const PublicLayout = lazy(() => import("./layouts/PublicLayout.tsx"));

// Public Pages
const Home = lazy(() => import("./pages/Home.tsx"));
const Login = lazy(() => import("./pages/auth/Login.tsx"));
const Signup = lazy(() => import("./pages/auth/Signup.tsx"));
const EmailSent = lazy(() => import("./pages/auth/EmailSent.tsx"));
const VerifyEmail = lazy(() => import("./pages/auth/VerifyEmail.tsx"));
const ForgotPassword = lazy(() => import("./pages/auth/ForgotPassword.tsx"));
const ResetPassword = lazy(() => import("./pages/auth/ResetPassword.tsx"));
const SSOSuccess = lazy(() => import("./pages/auth/SSOSuccess.tsx"));

// Not Found
const NotFound = lazy(() => import("./pages/NotFound.tsx"));

createRoot(document.getElementById("root")!).render(
  <BrowserRouter>
    <Suspense fallback={<FullScreenLoader />}>
      <Routes>
        <Route element={<PublicLayout />}>
          <Route index element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/email-sent" element={<EmailSent />} />
          <Route path="/verify-email/:verificationToken" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/sso-success" element={<SSOSuccess />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  </BrowserRouter>
);
