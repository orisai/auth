<?php declare(strict_types = 1);

$ignoreErrors = [];
$ignoreErrors[] = [
	'rawMessage' => 'Parameter #1 $id of class Orisai\\TranslationContracts\\TranslatableMessage constructor expects literal-string, mixed given.',
	'identifier' => 'argument.type',
	'count' => 1,
	'path' => __DIR__ . '/../src/Authentication/Data/ExpiredLogin.php',
];

return ['parameters' => ['ignoreErrors' => $ignoreErrors]];
