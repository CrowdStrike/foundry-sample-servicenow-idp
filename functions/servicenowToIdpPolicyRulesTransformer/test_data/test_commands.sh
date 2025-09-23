printf "\n\nUsing function_request_transform.json\n"

JSON_CONTENT=$(cat function_request_transform.json)
curl -X POST --location 'http://localhost:8081' \
--header 'Content-Type: application/json' \
--data "{
    \"body\": $JSON_CONTENT,
    \"method\": \"POST\",
    \"url\": \"/get-data-transform\"
}"
