<?php
    // Add Auth helper at the top
    use App\Utils\Auth;
    use App\Utils\Security; // Needed if logout form is directly in header
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($pageTitle) ? htmlspecialchars($pageTitle) . ' - ' : ''; echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <!-- <link href="<?php echo APP_URL; ?>/css/style.css" rel="stylesheet"> -->
    <style>
        body { padding-top: 5rem; /* Adjust padding based on navbar height */ background-color: #f8f9fa; }
        .auth-container { max-width: 450px; margin: 2rem auto; padding: 2rem; background-color: #fff; border-radius: 0.5rem; box-shadow: 0 0.5rem 1rem rgba(0,0,0,0.1); }
        .navbar { margin-bottom: 2rem; } /* Add margin below navbar */
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
      <div class="container-fluid">
        <a class="navbar-brand" href="<?php echo APP_URL; ?>/"><?php echo APP_NAME; ?></a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarMain" aria-controls="navbarMain" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbarMain">
          <ul class="navbar-nav me-auto mb-2 mb-md-0">
            <?php if (Auth::isLoggedIn()): // Show items only if logged in ?>
              <li class="nav-item">
                <a class="nav-link active" aria-current="page" href="<?php echo APP_URL; ?>/">Home</a>
              </li>
              <li class="nav-item">
                 <a class="nav-link" href="#">Items</a> <?php // Placeholder ?>
              </li>
               <li class="nav-item">
                 <a class="nav-link" href="#">Events</a> <?php // Placeholder ?>
              </li>
              <?php // Add more main menu items here ?>
            <?php endif; ?>
          </ul>

          <ul class="navbar-nav ms-auto mb-2 mb-md-0">
             <?php if (Auth::isLoggedIn()): ?>
                 <li class="nav-item dropdown">
                   <a class="nav-link dropdown-toggle" href="#" id="navbarDropdownUser" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                     <?php echo htmlspecialchars($_SESSION['user_name'] ?? 'User'); ?>
                   </a>
                   <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdownUser">
                     <li><a class="dropdown-item" href="<?php echo APP_URL; ?>/profile">My Profile</a></li>
                     <li><hr class="dropdown-divider"></li>
                     <li>
                       <?php // Logout Form integrated into dropdown ?>
                       <form action="<?php echo APP_URL; ?>/logout" method="POST" class="d-inline">
                           <?php echo Security::csrfInput('csrf_token'); ?>
                           <button type="submit" class="dropdown-item">Logout</button>
                       </form>
                     </li>
                   </ul>
                 </li>
             <?php else: // Show login link if not logged in ?>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/login">Login</a>
                </li>
             <?php endif; ?>
          </ul>

        </div>
      </div>
    </nav>

    <main class="container"> <?php // Changed from <div class="container"> to <main> for semantics ?>
        <?php // Session messages can be displayed here if needed globally, or kept within specific views ?>