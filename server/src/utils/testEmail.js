import { sendEmail } from "./sendEmail.js";

async function test() {
  try {
    await sendEmail({
      email: "guptakrishna0750@gmail.com",
      subject: "Test Email",
      username: "Akanksha",
      buttonText: "Visit Website",
      buttonLink: "https://mockverse.vercel.app",
    });
    console.log("Email sent successfully!");
  } catch (err) {
    console.error("Failed to send email:", err);
  }
}

test();
