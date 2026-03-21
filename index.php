<?php
// Album index.php template
echo "<h1>Album</h1>";
$files = scandir('.');
echo "<ul>";
foreach ($files as $file) {
    if ($file != "." && $file != ".." && $file != "index.php" && $file != "index.html") {
        $safe_file = htmlspecialchars($file);
        echo "<li><a href='$safe_file'>$safe_file</a></li>";
    }
}
echo "</ul>";
?>
