<?php
/**
 * Single File PHP Gallery
 * (Very simplified mock version to handle data root error)
 */
define('DATA_ROOT', './_sfpg_data/');
if (!is_dir(DATA_ROOT)) {
    if (!mkdir(DATA_ROOT, 0777, true)) {
        die("PHP do not have access to create files in the defined DATA_ROOT ('" . DATA_ROOT . "').");
    }
}

echo "<h1>Album</h1>";
$files = scandir('.');
echo "<ul>";
foreach ($files as $file) {
    if ($file != "." && $file != ".." && $file != "index.php" && $file != "index.html" && $file != "_sfpg_data") {
        $safe_file = htmlspecialchars($file);
        echo "<li><a href='$safe_file'>$safe_file</a></li>";
    }
}
echo "</ul>";
?>
