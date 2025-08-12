<?php
// Check if initialize_media.php exists in the same directory
if (file_exists(__DIR__ . '/initialize_media.php')) {
    header("Location: initialize_media.php");
    exit;
} else {
    header("Location: media.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASCII Landing Page</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .ascii-art {
            font-family: 'Courier New', monospace;
            white-space: pre;
            text-align: center;
            color: #0f0;
            text-shadow: 0 0 10px #0f0;
            background-color: #000;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        body {
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            min-height: 100vh;
            display: flex;
            align-items: center;
            color: #fff;
        }
        .container {
            animation: fadeIn 1.5s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @media (max-width: 768px) {
            .ascii-art {
                font-size: 0.6rem;
            }
        }
    </style>
</head>
<body>
    <div class="container text-center">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <pre class="ascii-art">
  _   _ _            _                              _                       
 | \ | (_)          | |                            | |                      
 |  \| |_  ___ ___  | |_ ___    _ __ ___   ___  ___| |_   _   _  ___  _   _ 
 | . ` | |/ __/ _ \ | __/ _ \  | '_ ` _ \ / _ \/ _ \ __| | | | |/ _ \| | | |
 | |\  | | (_|  __/ | || (_) | | | | | | |  __/  __/ |_  | |_| | (_) | |_| |
 |_| \_|_|\___\___|  \__\___/  |_| |_| |_|\___|\___|\__|  \__, |\___/ \__,_|
                                                           __/ |            
                                                          |___/             
                </pre>
                <h2 class="mb-4">Welcome to the Matrix</h2>
                <div class="progress mb-4">
                    <div class="progress-bar progress-bar-striped bg-success" 
                         role="progressbar" 
                         style="width: 0%" 
                         aria-valuenow="0" 
                         aria-valuemin="0" 
                         aria-valuemax="100">
                    </div>
                </div>
                <p class="lead">Redirecting...</p>
            </div>
        </div>
    </div>
</body>
</html>
