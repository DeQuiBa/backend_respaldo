const nodemailer = require("nodemailer");
require("dotenv").config();

const transporter = nodemailer.createTransport({
  host: "smtp-relay.sendinblue.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER, 
    pass: process.env.SMTP_PASS  
  }
});

async function enviarCorreo(destinatario, asunto, html) {
  try {
    await transporter.sendMail({
      from: `"SISGEFI-DK" <quibasheldon@gmail.com>`,
      to: destinatario,
      subject: asunto,
      html
    });
    console.log("Correo enviado a:", destinatario);
  } catch (error) {
    console.error("Error al enviar correo:", error);
  }
}

module.exports = { enviarCorreo };
