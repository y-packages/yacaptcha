# YakNet yaCaptcha Client SDK (`yaknet/yacaptcha`)

Official PHP integration SDK for the **YakNet yaCaptcha (Altcha-based) Protection Platform** (`auth.yakhub.com.tr`). This library provides a simple and secure PHP interface for displaying and verifying captchas without external dependencies like Guzzle (using native PHP cURL).

---

## Requirements

- PHP `>= 8.2`
- `ext-curl` enabled
- `ext-json` enabled

---

## Installation

You can install this package using Composer:

```bash
composer require yaknet/yacaptcha
```

*(Note: Ensure your repository is configured to access the private or custom packagist endpoint if this library is self-hosted, or install via local path repository).*

---

## Configuration

Copy the `.env.example` variables to your application's `.env` file and set your credentials:

```bash
YACAPTCHA_CLIENT_ID="your-client-id-here"
YACAPTCHA_CLIENT_SECRET="your-client-secret-here"
YACAPTCHA_BASE_URL="https://auth.yakhub.com.tr"
```

---

## Basic Usage

### 1. Render the yaCaptcha Widget

To display the captcha on your form page, generate the widget HTML and load the required JavaScript module:

```php
use YakNet\YaCaptcha\YaCaptcha;

// Initialize the client using environment variables
$yaCaptcha = new YaCaptcha(
    getenv('YACAPTCHA_CLIENT_ID') ?: '',
    getenv('YACAPTCHA_CLIENT_SECRET') ?: '',
    getenv('YACAPTCHA_BASE_URL') ?: 'https://auth.yakhub.com.tr'
);

// Render the widget script tag (typically loaded in head or footer)
echo $yaCaptcha->getScriptTag();
?>

<form action="submit.php" method="POST">
    <!-- Your form fields -->
    <input type="text" name="username" placeholder="Username" required>
    
    <!-- Render the yaCaptcha Widget -->
    <?php echo $yaCaptcha->getWidgetHtml(); ?>

    <button type="submit">Submit</button>
</form>
```

#### Customizing Widget Attributes

You can pass custom challenge URLs and HTML attributes:

```php
echo $yaCaptcha->getWidgetHtml('', [
    'auto' => 'onfocus',         // Options: 'onload', 'onfocus', 'off'
    'hideogo' => 'true',         // Hide the Altcha/yaCaptcha logo
    'class' => 'my-custom-class' // Custom CSS class for styling
]);
```

---

### 2. Verify the Captcha on Submit

When the user submits the form, the widget attaches a parameter named `altcha` containing the solution payload. Verify this payload in your backend script:

```php
use YakNet\YaCaptcha\YaCaptcha;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $payload = $_POST['altcha'] ?? '';

    $yaCaptcha = new YaCaptcha(
        getenv('YACAPTCHA_CLIENT_ID') ?: '',
        getenv('YACAPTCHA_CLIENT_SECRET') ?: '',
        getenv('YACAPTCHA_BASE_URL') ?: 'https://auth.yakhub.com.tr'
    );

    // Verify the payload with YakNet Auth server
    if ($yaCaptcha->verify($payload)) {
        // Captcha validation success! Proceed with form action
        echo "Validation successful! Processing form...";
    } else {
        // Captcha validation failed! Reject the request
        http_response_code(400);
        echo "Captcha validation failed. Please try again.";
        exit;
    }
}
```

---

## Testing

Run unit tests via PHPUnit:

```bash
vendor/bin/phpunit
```

Run static code analysis via PHPStan:

```bash
vendor/bin/phpstan analyse
```

---

## License

This project is developed by **YakNet Bilişim** and licensed under the **MIT License**.
