<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="style.css">
    <title>Page de Connexion</title>
</head>
<?php 
    if (!empty($_FILES)) {
        die("L'upload de fichiers est interdit !");
    } 
    session_start([
        'cookie_httponly' => true,  // Empêche l'accès JavaScript
        'cookie_secure' => true,    // Seulement en HTTPS
        'cookie_samesite' => 'Strict' // Empêche les attaques CSRF
    ]);   
?>
<body>
    <div id="logo">
        <img src="logo_google.png" alt="logo_google">
    </div>
    <form method="post">
        <div id="informations">
            <div id="label">
                <label for="email_box">Email</label>
                <label for="mdp">Mot de passe</label>
            </div>
            <div id="data">
                <input type="email" name="email" id="email_box" required>
                <input type="password" name="password" id="mot_de_passe" required>
            </div>
        </div>
        <div id="bouttons">
            <input type="reset" value="Reset" name="action">
            <input type="submit" value="Valider" name="action">
            <input type="submit" value="Ajout" name="action">
        </div>

        <?php
        $actions_autorisees = ["Valider", "Ajout", "Reset"];
        if (!isset($_POST['action']) || !in_array($_POST['action'], $actions_autorisees)) {
            die("Action non autorisée !");
        }
        
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            if (isset($_POST['action']) && $_POST['action'] !== "Reset") {
                $action = $_POST['action'];

                // Connexion à MySQL
                $config = include(__DIR__ . "/config/config.php");

                $conn = new mysqli(
                    $config["DB_HOST"], 
                    $config["DB_USER"], 
                    $config["DB_PASS"], 
                    $config["DB_NAME"]
                );


                // Vérification de la connexion
                if ($conn->connect_error) {
                    die("La connexion a échoué: " . $conn->connect_error);
                } ;

                // Sécuriser les entrées utilisateurs
                $email = isset($_POST['email']) ? filter_var($_POST['email'], FILTER_SANITIZE_EMAIL) : "";
                $email =  htmlspecialchars($email) ;
                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    die("Email invalide.");
                    exit();
                }
                $password = isset($_POST['password']) ? htmlspecialchars($_POST['password']) : "";

                if (empty($email) || empty($password)) {
                    die("Email ou mot de passe manquant!");
                    exit();
                }

                if ($action == "Valider") {
                    // Vérification de l'utilisateur
                    $stmt = $conn->prepare("SELECT * FROM utilisateurs WHERE email = ?");
                    $stmt->bind_param("s", $email);
                    $stmt->execute();
                    $result = $stmt->get_result();

                    if ($result->num_rows > 0) {
                        $user = $result->fetch_assoc();
                        if (password_verify($password, $user['password'])) {
                            echo htmlspecialchars("Connexion réussie!");
                        } else {
                            echo htmlspecialchars("Mot de passe incorrect.");
                        }
                    } else {
                        echo htmlspecialchars("Aucun utilisateur trouvé avec cet email.");
                    }
                } elseif ($action == "Ajout") {
                    // Vérification si l'email existe déjà
                    $stmt = $conn->prepare("SELECT * FROM utilisateurs WHERE email = ?");
                    $stmt->bind_param("s", $email);
                    $stmt->execute();
                    $result = $stmt->get_result();

                    if ($result->num_rows > 0) {
                        echo htmlspecialchars("Un utilisateur avec cet email existe déjà.");
                    } else {
                        // Ajouter l'utilisateur avec un mot de passe haché
                        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                        $stmt = $conn->prepare("INSERT INTO utilisateurs (email, password) VALUES (?, ?)");
                        $stmt->bind_param("ss", $email, $hashed_password);

                        if ($stmt->execute()) {
                            echo htmlspecialchars("Utilisateur ajouté avec succès!");
                        } else {
                            echo htmlspecialchars("Erreur lors de l'ajout de l'utilisateur.");
                        }
                    }
                }

                $conn->close();
            }
        }
        ?>
    </form>
</body>
</html>
