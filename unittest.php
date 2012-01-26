<?PHP

require_once("Flickr.php");


$f = new Flickr();
$f->signIntoFlickr();

echo "logged in<pre>";


print_r($_SESSION);
?>

</pre>

