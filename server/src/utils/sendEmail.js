import nodemailer from "nodemailer";
import Mailgen from "mailgen";
import dotenv from "dotenv";

dotenv.config();

export const sendEmail = async ({ email, subject, username, buttonText, buttonLink }) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: process.env.FROM_NAME,
      link: process.env.FRONTEND_URL,
    },
  });

  const emailContent = {
    body: {
      name: username,
      intro: "You requested to reset your password.",
      action: {
        instructions: "Click the button below to reset your password:",
        button: {
          color: "#22BC66",
          text: buttonText,
          link: buttonLink,
        },
      },
      outro: "If you didn't request this, you can ignore this email.",
    },
  };

  const emailBody = mailGenerator.generate(emailContent);
  const emailText = mailGenerator.generatePlaintext(emailContent);

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const mailOptions = {
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
    to: email,
    subject,
    html: emailBody,
    text: emailText,
  };

  await transporter.sendMail(mailOptions);
};
