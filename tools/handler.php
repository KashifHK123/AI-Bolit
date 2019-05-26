<?php

// when scanning process starts
function aibolit_onStart() {
   // TODO...
}

// when scanning process ends
function aibolit_onComplete($exit_code, $stat) {
   // TODO...
}

// when progress updates
function aibolit_onProgressUpdate($data) {
   // TODO...
}

// error when reading file
function aibolit_onReadError($path, $type) {
   // TODO...
}

// when skips big file
function aibolit_onBigFile($path) {
   // TODO...
}

// when some fatal error occurs
function aibolit_onFatalError($errstr) {
   // TODO...
}