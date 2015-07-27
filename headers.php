<html>
<head>
<title>
Security Header Review
</title>
<link rel="stylesheet" type="text/css" href="basic.css">
</head>
<body>
<div class="container">
    <div class="header">
    <h1>Check your headers here!</h1>
    </div>
<div class="content">
<?php if($_POST["submit"]) { ?>
<!-- This will display if the form has been submitted. -->
<h2>Results for <?php echo htmlentities($_POST["domain"]) ?></h2>

<?php
function &get_results() {
  // Pulls domains from POST and grabs headers;
  $domain = htmlentities($_POST["domain"]);
  // Adds protocol if none entered on form
  if (stripos($domain, "http") !== 0) {
    $domain = "http://".$domain;
  }
  file_get_contents($domain);
  global $header;
  $header = $http_response_header;
  return $header;
}
function secure_header(&$header) {
  // Checks for OWASP recommended secure headers
  // Creates array of headers with all keys being lowercase
  $headerArray = array();
  foreach($header as $headerValue){
    $headerSplit = explode(": ", $headerValue);
    $headerKey = strtolower($headerSplit[0]);
    $headerArray[$headerKey] = $headerSplit[1];    
  }
  //print_r($headerArray);
  // Loops through headers based on Keys
  if (array_key_exists("cache-control", $headerArray)) {    
    if (stripos($headerArray["cache-control"], "no-cache") !== false && strpos($headerArray["cache-control"], "no-store") !== false) {
        echo "<font style='color:green'>Cache-control is OK</font><br>";
    } else {
        echo "<font style='color:orange'>Check cache-control</font><br>";
    }
  } else {
    echo "<font style='color:red'>Cache-control not enabled</font><br>";
  }
  if (array_key_exists("pragma", $headerArray)) {
    echo "<font style='color:green'>Pragma is OK</font><br>";
  } else {
    echo "<font style='color:red'>Pragma not enabled</font><br>";
  }
  if (array_key_exists("content-type", $headerArray)) {
    if  (stripos($headerArray["content-type"], "text/html") !== false) {
        echo "<font style='color:green'>Content-type set for text/html</font><br>";
    } else {
        echo "<font style='color:orange'>Check content-type for text/html</font><br>";
    }
  } else {
    echo "<font style='color:red'>Content-type not enabled</font><br>";
  }
  if (array_key_exists("content-type", $headerArray)) {
    if  (stripos($headerArray["content-type"], "charset") !== false) {
        echo "<font style='color:green'>Content-type set for charset</font><br>";
    } else {
        echo "<font style='color:orange'>Check content-type for charset</font><br>";
    }
  } else {
    echo "<font style='color:red'>Content-type not enabled</font><br>";
  }
  if (array_key_exists("access-control-allow-origin", $headerArray)) {
    echo "<font style='color:green'>Access-control-allow-origin is enforced</font><br>";
  } else {
    echo "<font style='color:red'>Access-control-allow-origin not enabled</font><br>";
  }
  if (array_key_exists("strict-transport-security", $headerArray)) {
    echo "<font style='color:green'>Strict-transport-security is enforced</font><br>";
  } else {
    echo "<font style='color:red'>Strict-transport-security not enabled</font><br>";
  }
  if (array_key_exists("x-content-type-options", $headerArray)) {
    echo "<font style='color:green'>X-content-type-options is enforced</font><br>";
  } else {
    echo "<font style='color:red'>X-content-type-options not enabled</font><br>";
  }
  if (array_key_exists("x-content-security-policy", $headerArray)) {
    echo "<font style='color:green'>X-content-security-policy is enforced</font><br>";
  } else {
    echo "<font style='color:red'>X-content-security-policy not enabled</font><br>";
  }
  if (array_key_exists("x-download-options", $headerArray)) {
    echo "<font style='color:green'>X-download-options is enforced</font><br>";
  } else {
    echo "<font style='color:red'>X-download-options not enabled</font><br>";
  }
  if (array_key_exists("x-xss-protection", $headerArray)) {
    echo "<font style='color:green'>X-XSS-protection is enforced</font><br>";
  } else {
    echo "<font style='color:red'>X-XSS-protection not enabled</font><br>";
  }
  if (array_key_exists("x-frame-options", $headerArray)) {
    echo "<font style='color:green'>X-frame-options is enforced</font><br>";
  } else {
    echo "<font style='color:red'>X-frame-options not enabled</font><br>";
  }
}
function build_results(&$header) {
  // Builds HTML table to display ALL headers;
  echo "<p><h3>Full header results</h3>";
  echo "<table><tr><th>Name</th><th>Value</th>";
  foreach($header as $headerValue){
    $headerSplit = explode(": ", $headerValue);
    echo "<tr><td>".$headerSplit[0]."</td>";
    echo "<td>".$headerSplit[1]."</td></tr>";
    }
  echo "</table>";
}
get_results();
secure_header($header);
build_results($header);
?>
<p>
<form action="headers.php" method="POST">
        <input class="btn" type="submit" name="reset" value="reset">
</form>
<?php } else { ?>
<!-- This will display upon initial load or resetting page. -->
<h2>Enter domain:</h2>
<form action="headers.php" method="POST">
        <input type="text" name="domain">
        <input class="btn" type="submit" name="submit" value="submit">
</form>
<?php } ?>
</div>
</div>
</body>
