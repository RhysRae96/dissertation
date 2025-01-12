<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require '../vendor/autoload.php'; // Ensure PHPMailer is installed via Composer

class EmailController {
    public function sendVerificationEmail($recipientEmail, $recipientName, $token) {
        $mail = new PHPMailer(true);

        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'rhysjamesrae@gmail.com';  // Your Gmail email
            $mail->Password = 'tgyl tpkt xoxd vgaz';        // Your Gmail app password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            // Enable debugging (set to 0 for production)
            $mail->SMTPDebug = 0;

            // Recipients
            $mail->setFrom('rhysjamesrae@gmail.com', 'Your Website');
            $mail->addAddress($recipientEmail, $recipientName);

            // Content
            $mail->isHTML(true);
            $mail->Subject = 'Verify Your Account';
            $mail->Body = '
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; margin: 0; padding: 0; }
        .email-container { background-color: #ffffff; max-width: 600px; margin: 20px auto; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
        .email-header { text-align: center; padding: 10px 0; }
        .email-header img { max-width: 100px; }
        .email-content { padding: 20px; text-align: center; color: #333333; }
        .email-content h1 { color: #333333; font-size: 24px; }
        .email-content p { font-size: 16px; line-height: 1.5; }
        .verify-button { display: inline-block; padding: 10px 20px; margin: 20px 0; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 18px; }
        .verify-button:hover { background-color: #45a049; }
        .email-footer { text-align: center; padding-top: 20px; color: #777777; font-size: 14px; }
        .email-footer a { color: #4CAF50; text-decoration: none; }
    </style>
</head>
<body>
      <div class="email-content">
            <h1>Verify Your Account</h1>
            <p>Hello ' . htmlspecialchars($recipientName) . ',</p>
            <p>Thank you for registering on our website. Please click the button below to verify your email address and activate your account.</p>
            <a href="http://localhost/dissertation/view/verify.php?token=' . $token . '" class="verify-button">Verify My Account</a>
            <p>If the button above does not work, please copy and paste the following link into your browser:</p>
            <p>http://localhost/dissertation/view/verify.php?token=' . $token . '</p>
        </div>
    </div>
</body>
</html>';

            $mail->AltBody = 'Please click the following link to verify your account: http://localhost/dissertation/view/verify.php?token=' . $token;

            // Send email
            $mail->send();
            echo 'Verification email sent successfully.';
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }
}
?>
<!-- 
tgyl tpkt xoxd vgaz -->