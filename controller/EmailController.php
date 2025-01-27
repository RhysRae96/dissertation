<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require '../vendor/autoload.php'; // Ensure PHPMailer is installed via Composer

class EmailController {
    public function sendChangePasswordEmail($recipientEmail, $recipientName, $changePasswordLink) {
        $mail = new PHPMailer(true);

        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'rhysjamesrae@gmail.com';  // Replace with your Gmail email
            $mail->Password = 'tgyl tpkt xoxd vgaz';     // Replace with your app password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            // Recipients
            $mail->setFrom('rhysjamesrae@gmail.com', 'Uni Authentication Project');
            $mail->addAddress($recipientEmail, $recipientName);

            // Email content
            $mail->isHTML(true);
            $mail->Subject = 'Change Your Password';
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
                    .button-container { text-align: center; margin: 20px 0; }
                    .change-password-button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 18px; }
                    .change-password-button:hover { background-color: #45a049; }
                    .email-footer { text-align: center; padding-top: 20px; color: #777777; font-size: 14px; }
                    .email-footer a { color: #4CAF50; text-decoration: none; }
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="email-header">
                        <h1>Change Your Password</h1>
                    </div>
                    <div class="email-content">
                        <p>Hello ' . htmlspecialchars($recipientName) . ',</p>
                        <p>Click the button below to change your password:</p>
                        <div class="button-container">
                            <a href="' . htmlspecialchars($changePasswordLink) . '" class="change-password-button">Change Password</a>
                        </div>
                        <p>If you did not request this, please ignore this email.</p>
                    </div>
                    <div class="email-footer">
                        <p>&copy; ' . date('Y') . ' Uni Authentication Project. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>';

            $mail->AltBody = "Hello $recipientName,\n\nClick the link below to change your password:\n\n$changePasswordLink\n\nIf you did not request this, please ignore this email.";

            // Send the email
            $mail->send();
            echo "Password change email sent successfully.";
        } catch (Exception $e) {
            echo "Mailer Error: " . $mail->ErrorInfo;
        }
    }

    public function sendVerificationEmail($recipientEmail, $recipientName, $activationToken) {
        $mail = new PHPMailer(true);

        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'rhysjamesrae@gmail.com'; // Your Gmail email
            $mail->Password = 'tgyl tpkt xoxd vgaz';    // Your Gmail app password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            // Recipients
            $mail->setFrom('rhysjamesrae@gmail.com', 'Uni Authentication Project');
            $mail->addAddress($recipientEmail, $recipientName);

            // Email content
            $verificationLink = "http://localhost/dissertation_usability/view/verify.php?token=" . $activationToken;

            $mail->isHTML(true);
            $mail->Subject = 'Verify Your Account';
            $mail->Body = '
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f9f9f9;
            margin: 0;
            padding: 0;
        }
        .email-container {
            background-color: #ffffff;
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .email-header {
            text-align: center;
            padding: 10px 0;
        }
        .email-header h1 {
            color: #333333;
            font-size: 24px;
        }
        .email-content {
            padding: 20px;
            text-align: center;
            color: #333333;
        }
        .email-content p {
            font-size: 16px;
            line-height: 1.5;
        }
        .button-container {
            text-align: center;
            margin: 20px 0;
        }
        .verify-button {
            display: inline-block;
            padding: 10px 20px;
            background-color: #4CAF50;
            color: #ffffff;
            text-decoration: none;
            border-radius: 5px;
            font-size: 18px;
        }
        .verify-button:hover {
            background-color: #45a049;
        }
        .email-footer {
            text-align: center;
            padding-top: 20px;
            color: #777777;
            font-size: 14px;
        }
        .email-footer a {
            color: #4CAF50;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="email-header">
            <h1>Email Verification</h1>
        </div>
        <div class="email-content">
            <p>Hello ' . htmlspecialchars($recipientName) . ',</p>
            <p>Thank you for registering on our website. Please click the button below to verify your email address:</p>
            <div class="button-container">
                <a href="' . htmlspecialchars($verificationLink) . '" class="verify-button">Verify My Account</a>
            </div>
            <p>If the button above does not work, please copy and paste the following link into your browser:</p>
            <p><a href="' . htmlspecialchars($verificationLink) . '">' . htmlspecialchars($verificationLink) . '</a></p>
        </div>
        <div class="email-footer">
            <p>&copy; ' . date('Y') . ' Uni Authentication Project. All rights reserved.</p>
        </div>
    </div>
</body>
</html>';
            $mail->send();
        } catch (Exception $e) {
            echo "Mailer Error: " . $mail->ErrorInfo;
        }
    }

    public function sendPasswordResetEmail($recipientEmail, $recipientName, $resetLink) {
        $mail = new PHPMailer(true);
    
        try {
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'rhysjamesrae@gmail.com';  // Replace with your Gmail
            $mail->Password = 'tgyl tpkt xoxd vgaz';     // Replace with your Gmail App password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;
    
            $mail->setFrom('rhysjamesrae@gmail.com', 'Uni Authentication Project');
            $mail->addAddress($recipientEmail, $recipientName);
    
            $mail->isHTML(true);
            $mail->Subject = 'Password Reset Request';
            $mail->Body = $mail->Body = '
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
                    .button-container { text-align: center; margin: 20px 0; }
                    .reset-button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 18px; }
                    .reset-button:hover { background-color: #45a049; }
                    .email-footer { text-align: center; padding-top: 20px; color: #777777; font-size: 14px; }
                    .email-footer a { color: #4CAF50; text-decoration: none; }
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="email-header">
                        <h1>Password Reset</h1>
                    </div>
                    <div class="email-content">
                        <p>Hello ' . htmlspecialchars($recipientName) . ',</p>
                        <p>Click the button below to reset your password:</p>
                        <div class="button-container">
                            <a href="' . htmlspecialchars($resetLink) . '" class="reset-button">Reset Password</a>
                        </div>
                        <p>If you did not request this password reset, please ignore this email.</p>
                        <p><strong>Note:</strong> This link will expire in 1 hour.</p>
                    </div>
                    <div class="email-footer">
                        <p>&copy; ' . date('Y') . ' Uni Authentication Project. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>';            
    
            $mail->AltBody = "Hello $recipientName,\n\nClick the link below to reset your password:\n$resetLink\n\nThis link will expire in 1 hour.";
    
            $mail->send();
        } catch (Exception $e) {
            echo "Mailer Error: " . $mail->ErrorInfo;
        }
    }
    
}
?>
<!-- 
tgyl tpkt xoxd vgaz -->