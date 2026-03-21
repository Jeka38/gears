<?php
// Album index.php template
echo "<h1>Album</h1>";
$files = scandir('.');
echo "<ul>";
foreach ($files as $file) {
    if ($file != "." && $file != ".." && $file != "index.php" && $file != "index.html") {
        echo "<li><a href='$file'>$file</a></li>";
    }
}
echo "</ul>";
?>
