<?php
require_once 'vendor/autoload.php';

use JsonSchema\Uri\UriRetriever;
use Webmozart\Json\JsonEncoder;
use Webmozart\Json\JsonDecoder;
use Webmozart\Json\JsonValidator;
use Webmozart\Json\UriRetriever\LocalUriRetriever;

/*$schema = [
    "title" =>"Example Schema",
	"type" =>"object",
	"properties" =>[
        "firstName" =>[
            "type" =>"string",
		],
		"lastName" =>[
            "type" =>"string",
		],
		"age" =>[
            "description" =>"Age in years",
			"type" =>"integer",
			"minimum" =>0,
		]
	],
	"required" =>["firstName", "lastName"],
];

file_put_contents(__DIR__.'/schema-1.0.json', json_encode($schema));*/

$uriRetriever = new UriRetriever();
$uriRetriever->setUriRetriever(new LocalUriRetriever(
// base directory
    __DIR__,
    // list of schema mappings
    array(
        'http://example.org/schemas/1.0/schema' => 'schema-1.0.json',
    )
));

$validator = new JsonValidator(null, $uriRetriever);

$encoder = new JsonEncoder($validator);
$decoder = new JsonDecoder($validator);

$data = new stdClass();
$data->firstName = '11';
$data->lastName = '11';

$data = $encoder->encode($data,'http://example.org/schemas/1.0/schema');
dump($data);
$data = $decoder->decode($data, 'http://example.org/schemas/1.0/schema');
dump($validator->validate($data, 'http://example.org/schemas/1.0/schema'));
dump($data);
