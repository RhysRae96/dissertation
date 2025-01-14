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
}
?>
<!-- 
tgyl tpkt xoxd vgaz -->