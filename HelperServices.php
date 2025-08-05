<?php
namespace RestMyApis\Services;

use Firebase\JWT\JWT;
use YITH_WCWL_Wishlist_Factory;
use YITH_WCWL_Wishlist_Item;
use YITH_WCWL_Wishlist;
use Bookly\Lib\Entities\Service;
use Bookly\Lib\Entities\Staff;
use Bookly\Lib\Entities\Slot;
use \WP_User;
use WP_REST_Response;


class HelperService {
    
    public static function generate_jwt_token( $user_id ) {
		// echo $user_id;die;
        $secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
        $payload = [
            'iss' => get_bloginfo('url'),
            'aud' => get_bloginfo('url'), 
            'iat' => time(), 
            'nbf' => time(),
			'exp' => time() + (7 * 24 * 60 * 60),
            'data' => [
				'user' => [
					'id' => $user_id,
				],
			],
        ];
        
        $algorithm = 'HS256'; 

        return JWT::encode($payload, $secret_key, $algorithm);
    }

    //Decode JWT token
    public static function decode_jwt_token($jwt) {
		try {
			// Split the JWT into its three parts (Header, Payload, Signature)
			list($header, $payload, $signature) = explode('.', $jwt);
			
			// Base64Url decode the header and payload
			$decoded_header = json_decode(self::base64UrlDecode($header), true);
			$decoded_payload = json_decode(self::base64UrlDecode($payload), true);
			
			// Manually verify 'iss' and 'aud' fields
			$expected_iss = get_bloginfo('url');
			$expected_aud = get_bloginfo('url');
			// print_r($expected_iss);print_r($expected_aud);
			// print_r($decoded_payload);die;

		
			// Optionally check expiration time if needed
			if (isset($decoded_payload['exp']) && time() > $decoded_payload['exp']) {
				 return new \WP_REST_Response([
					'success' => false,
					'message' => 'Token has expired'
				], 401);
			}

			// Return the decoded payload (this is the decoded JWT data)
			return $decoded_payload;

		} catch (\Exception $e) {
			// Log and return null if any error occurs
			error_log('JWT Decode Error: ' . $e->getMessage());
			return null;
		}
	}

	public static function base64UrlDecode($base64Url) {
		// Replaces base64Url chars with base64 chars
		$base64 = strtr($base64Url, '-_', '+/');
		return base64_decode(str_pad($base64, strlen($base64) % 4, '=', STR_PAD_RIGHT));
	}


    // Function to validate JWT token
	public static function validate_jwt_token( $request) {
		// Get the Authorization header from the request
		$auth_header = $request->get_header('Authorization');

		if (!$auth_header) {
		  return new \WP_REST_Response([
				'success' => false,
				'message' => 'Authorization header is missing'
			], 401);
		}

		// Extract token (Bearer <token>)
		$bearer_token = str_replace('Bearer ', '', $auth_header);

		// Decode JWT token
		$decoded = self::decode_jwt_token($bearer_token);
		

		if (!$decoded) {
		  return new \WP_REST_Response([
				'success' => false,
				'message' => 'Invalid or expired token.'
			], 401);
		}

		// If token is valid, return true to proceed with other logic
		return true;
	}	

	public static function get_wishlist_count($user_id) {
		
		$wishlist = YITH_WCWL_Wishlist_Factory::generate_default_wishlist($user_id);
		if (!$wishlist) {
			return 0;
		}

		// Count the items in the wishlist
		$wishlist_items = $wishlist->get_items();
		$count = count($wishlist_items);

		return $count;
	}
    //Fetch user details
    public static function get_user_details($user_id){
		$user = get_userdata($user_id);
		if(!$user)
		{
			return null;
		}
		
		$wishlist_count = self::get_wishlist_count($user_id);
		$user_details = [
				'id'       => $user->ID,
				'username' => $user->user_login,
				'email'	   => $user->user_email,
				'firstname'=> get_user_meta($user->ID,'first_name', true),
				'lastname' => get_user_meta($user->ID,'last_name', true),
				'role'	   => $user->roles,
				'wishlist_count' => $wishlist_count,
				];
		//Role specific fields
		$user_other_data=[];
		//normal user
		if(in_array('subscriber', $user->roles)){
				$user_other_data = [
									'country' => get_user_meta($user->ID, 'user_registration_country_1623050729', true),
									'dob' => get_user_meta($user->ID, 'user_registration_date_box_1623051693', true),
									'Gender' => get_user_meta($user->ID, 'user_registration_radio_1623051748', true),
									'city' => get_user_meta($user->ID, 'user_registration_input_box_1623050696', true),
									'pincode' => get_user_meta($user->ID, 'user_registration_input_box_1623050879', true),
									'state' => get_user_meta($user->ID, 'user_registration_input_box_1623050759', true),
									'phone' => get_user_meta($user->ID, 'user_registration_phone', true),
									
									];
		}
		// 	//service provider
		// 	elseif(in_array('Services_provider', $user->roles)){
		// 			$user_other_data = [
		// 								'field1' => get_user_meta($user->ID, 'field1', true),
		// 								];
		// 	}
		
		return array_merge($user_details, $user_other_data);
		
	}
	
	
public static function validate_user_credentials($identifier, $password, $fcm_tokens) {
    error_log('fcm_tokens: ' . print_r($fcm_tokens, true));

    if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
        $user = get_user_by('email', $identifier);
    } else {
        $user = get_user_by('login', $identifier);
    }

    if (!$user) {
        return [
            'success' => false,
            'message' => 'Invalid Username Or Email.',
        ];
    }

    if (!wp_check_password($password, $user->data->user_pass, $user->ID)) {
        return [
            'success' => false,
            'message' => 'Invalid Password.',
        ];
    }

    $user_id   = $user->ID;
    $user_meta = get_user_meta($user_id);
    $roles     = $user->roles;

    // ✅ Only update the device token if it's not empty and not null
    if (!empty($fcm_tokens)) {
        $existing_tokens = get_user_meta($user_id, 'device_login_tokens', true); // Get current device tokens

        // If no tokens exist, initialize as an empty array
        if (empty($existing_tokens)) {
            $existing_tokens = [];
        }

        // Ensure $fcm_tokens is an array (in case it's a single token, convert it to an array)
        if (!is_array($fcm_tokens)) {
            $fcm_tokens = (array) $fcm_tokens;
        }

        // Merge new tokens with the existing ones, avoiding duplicates
        $new_tokens = array_merge($existing_tokens, $fcm_tokens); // Merge arrays
        $new_tokens = array_unique($new_tokens); // Remove duplicates

        // Update the user meta with the new tokens
        $updated = update_user_meta($user_id, 'device_login_tokens', $new_tokens);

        // Optional: Check if the update was successful
        if ($updated) {
            error_log('Device tokens updated successfully for user ID: ' . $user_id);
        } else {
            error_log('Failed to update device tokens for user ID: ' . $user_id);
        }
    } else {
        error_log('No FCM tokens provided for user ID: ' . $user_id);
    }

    // ✅ Service Provider status check
    if (in_array('services_provider', $roles)) {
        $status = isset($user_meta['ur_user_status'][0]) ? (int)$user_meta['ur_user_status'][0] : 0;

        if ($status === -1) {
            return [
                'success' => false,
                'message' => 'Your account has been denied. Please contact support.',
            ];
        } elseif ($status === 0) {
            return [
                'success' => false,
                'message' => 'Your account is pending approval. Please wait for confirmation.',
            ];
        }
    }

    global $wpdb;
    $staff_id = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT id FROM {$wpdb->prefix}bookly_staff WHERE wp_user_id = %d",
            $user_id
        )
    );

    // Phone number added here for ALL users
    $user_details = [
        'id'             => $user_id,
        'username'       => $user->user_login,
        'email'          => $user->user_email,
        'firstname'      => $user_meta['first_name'][0] ?? '',
        'lastname'       => $user_meta['last_name'][0] ?? '',
        'display_name'   => $user->display_name,
        'role'           => $roles,
        'phone_number'   => $user_meta['phone_number'][0] ?? '',
        'wishlist_count' => 0,
    ];

    if (in_array('services_provider', $roles)) {
        $user_details = array_merge($user_details, [
            'staff_id'             => $staff_id ?: '',
            'selected_category_id' => $user_meta['selected_category_id'][0] ?? '',
            'house_area'           => $user_meta['house_area'][0] ?? '',
            'gali_sector'          => $user_meta['gali_sector'][0] ?? '',
            'city'                 => $user_meta['city'][0] ?? '',
            'pin_code'             => $user_meta['pin_code'][0] ?? '',
        ]);
    }

    // 🪙 Add JWT Token
    $token = self::generate_jwt_token($user_id);
    $user_details['token'] = $token;

    // Send Push Notification after successful login
    $push_message = 'You have successfully logged in!';
    // self::sendPushNotification($fcm_tokens, "Welcome!");
    // Call the sendPushNotification function

    return [
        'success' => true,
        'message' => 'Login Successful.',
        'data'    => $user_details,
    ];
}




public static function sendPushNotification($fcm_tokens, $title = "", $message = "", $customData = []) {
    $url = 'https://exp.host/--/api/v2/push/send';
	   // Log the customData for debugging
  

    // Ensure $fcm_tokens is an array
    if (!is_array($fcm_tokens)) {
        error_log('Invalid FCM tokens provided. It should be an array.');
        return; // Early exit if FCM tokens are not an array
    }
    // Build the data payload
    $data = array_merge([
        'customData' => 'value',  // Default custom data
        'screen' => '/service/view-booking',  // Example static screen
        //'id' => 123,  // Example dynamic ID
        'type' => 'service_provider',  // Example static type
    ], $customData);  // Merge additional dynamic custom data passed to the function
  error_log('Custom Data for Push Notification: ' . print_r($data, true));
    // Build the complete payload
    $payload = json_encode([
        'to' => $fcm_tokens,  // Ensure $fcm_tokens is an array of valid tokens
        'sound' => 'default',
        'title' => $title,
        'body' => $message,
        'data' => $data,  // The custom data here
    ]);

    // Initialize cURL
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/json',
        'Accept-Encoding: gzip, deflate',
        'Content-Type: application/json',
        // 'Authorization: Bearer YOUR_API_KEY'  // Add if you need auth
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    
    // Optional: Set timeout for cURL request
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);

    // Execute cURL request
    $response = curl_exec($ch);

    // Get HTTP status code
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    // Log the HTTP status code for debugging
    error_log('HTTP Status Code: ' . $http_code);
    
    if ($response === false) {
        // Log the cURL error if request fails
        error_log('Push Notification cURL Error: ' . curl_error($ch));
    } else {
        // Log the response from the server
        $responseData = json_decode($response, true);
        error_log('Push Notification Response: ' . print_r($responseData, true));
        
        // Additional logging based on HTTP status
        if ($http_code != 200) {
            // Log the error if the response code is not 200
            error_log('Error sending push notification. Response code: ' . $http_code);
            error_log('Response body: ' . $response);
        }
    }

    curl_close($ch);
}



	
public static function handle_logout_with_expo($request) {

    // Get the FCM device token from the request (sent via POST parameter)
    $fcm_device_token = $request->get_param('token'); // e.g., 'ExponentPushToken[sdf;ljdsfjsdlkfj]'

	$auth_header = $request->get_header('Authorization');

		if (!$auth_header) {
		  return new \WP_REST_Response([
				'success' => false,
				'message' => 'Authorization header is missing'
			], 401);
		}

		// Extract token (Bearer <token>)
		$bearer_token = str_replace('Bearer ', '', $auth_header);

		// Decode JWT token
		$decoded = self::decode_jwt_token($bearer_token);
		//echo "<pre>"; print_r($decoded);die;
    // Ensure the token is provided
    if (empty($fcm_device_token)) {
        return new WP_Error('missing_token', 'FCM Device token is required.', ['status' => 400]);
    }

    // Get the current user ID (assuming the user is logged in)
    $user_id = get_current_user_id();
    if (!$user_id) {
        return new WP_Error('not_logged_in', 'User is not logged in.', ['status' => 401]);
    }

    // Fetch the stored FCM tokens from user meta (device_login_tokens)
    $stored_fcm_tokens = get_user_meta($user_id, 'device_login_tokens', true); // Fetch tokens as an array

    // Ensure that the tokens are stored as an array
    if (empty($stored_fcm_tokens) || !is_array($stored_fcm_tokens)) {
        return new WP_Error('no_tokens', 'No FCM tokens found for this user.', ['status' => 404]);
    }

    // Check if the provided token exists in the user's stored tokens
    if (in_array($fcm_device_token, $stored_fcm_tokens)) {
        // Token found, proceed with logout (remove the token from the list)

        // Remove the provided token from the array
        $updated_fcm_tokens = array_diff($stored_fcm_tokens, [$fcm_device_token]);

        // If the token was the only one, the array will become empty
        if (empty($updated_fcm_tokens)) {
            delete_user_meta($user_id, 'device_login_tokens');  // If no tokens remain, delete the field entirely
        } else {
            // Update the user meta with the updated token list (remove the token from the list)
            update_user_meta($user_id, 'device_login_tokens', $updated_fcm_tokens);
        }

        // Optionally: Log the user out from WordPress (invalidates the session)
        wp_logout();

        // Return success message
        return [
            'status' => 'success',
            'message' => 'Logout successful. Device token has been removed.'
        ];
    } else {
        // Token not found in the user's stored tokens
        return new WP_Error('token_not_found', 'FCM device token not found for this user.', ['status' => 404]);
    }
}



	public static function validate_user_credentials_with_identifier($identifier,$token) {
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Headers: *");
	
		if(filter_var($identifier, FILTER_VALIDATE_EMAIL))
		{
			$user = get_user_by('email', $identifier);
			$error_message = 'Invalid Email.';
		}
		else {
			$users = get_users([
				'meta_key'   => 'user_registration_phone', 
				'meta_value' => $identifier,
				'number'     => 1, 
			]);

			$user = !empty($users) ? $users[0] : false;
			$error_message = 'Phone number not registered.';
		}
		// echo "<pre>"; print_r($user); die;
		if(!$user)
		{
			return [
					'success' => false,
					'message' => $error_message,
			];
		}
		$otp = rand(1000, 9999); 
		$user_id = $user->ID;
		
		update_user_meta($user_id, 'otp_code', $otp);
		update_user_meta($user_id, 'otp_expiry', time() + 300);
		
		 // ✅ Add token to user meta if provided
		if (!empty($token)) {
        $existing_token = get_user_meta($user_id, 'device_login_tokens', true);
        if ($existing_token !== $token) {
            update_user_meta($user_id, 'device_login_tokens', $token);
        }
    }

		if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
			$otp_response = send_email_otp($identifier, $otp);
			return $otp_response;
		} else {
			update_user_meta($user_id, 'phone_number', $identifier);
			$otp_response = send_phone_otp($identifier, $otp);
			
			 return $otp_response;	
		}
	}
	
	
	//handle_user_orders_details
public static function handle_orders_details_user($request) {
   $user_id = get_current_user_id();

    if (!$user_id) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'User not logged in.',
        ], 401);
    }

    $today = date('Y-m-d');
    global $wpdb;

    $customer_data = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT id FROM {$wpdb->prefix}bookly_customers WHERE wp_user_id = %d",
            $user_id
        )
    );

    $today_appointments = [];
    $history_appointments = [];
    $future_appointments = [];

    if ($customer_data) {
        $customer_id = $customer_data->id;

        $appointments = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT a.id, a.start_date 
                 FROM {$wpdb->prefix}bookly_appointments a
                 INNER JOIN {$wpdb->prefix}bookly_customer_appointments ca ON ca.appointment_id = a.id
                 WHERE ca.customer_id = %d",
                $customer_id
            )
        );

        foreach ($appointments as $appt) {
            $appt_date = date('Y-m-d', strtotime($appt->start_date));
            $appt_entry = [
                'appointment_id' => $appt->id,
                'date' => $appt_date, // Only the date
            ];

            if ($appt_date === $today) {
                $today_appointments[] = $appt_entry;
            } elseif ($appt_date < $today) {
                $history_appointments[] = $appt_entry;
            } else {
                $future_appointments[] = $appt_entry;
            }
        }
    }

    // Build summary string output
    $summary = "Today's Orders:\n";
    if (!empty($today_appointments)) {
        foreach ($today_appointments as $appt) {
            $summary .= "Appointment #{$appt['appointment_id']} - Date: {$appt['date']}\n";
        }
    } else {
        $summary .= "No appointments scheduled for today.\n";
    }

    $summary .= "\nOrders History:\n";
    if (!empty($history_appointments)) {
        foreach ($history_appointments as $appt) {
            $summary .= "Appointment #{$appt['appointment_id']} - Date: {$appt['date']}\n";
        }
    } else {
        $summary .= "No past appointments found.\n";
    }

    $summary .= "\nFuture Orders:\n";
    if (!empty($future_appointments)) {
        foreach ($future_appointments as $appt) {
            $summary .= "Appointment #{$appt['appointment_id']} - Date: {$appt['date']}\n";
        }
    } else {
        $summary .= "No future appointments scheduled.\n";
    }

    // Return JSON with summary
    $response = [
        'success' => true,
        'data' => [
            'today_appointments' => $today_appointments,
            'history_appointments' => $history_appointments,
            'future_appointments' => $future_appointments,
        ],
        'summary' => $summary
    ];

    return new WP_REST_Response($response, 200);
}



	public static function handle_service_provider_details($request) {
    $user_id = $request['user_id'];
 
    if (empty($user_id) || !get_user_by('id', $user_id)) {
        return new \WP_REST_Response([
            'success' => false,
            'message' => 'Invalid or missing user ID.',
        ], 400);
    }
 
    $all_meta = get_user_meta($user_id);
    $allowed_keys = [
        'phone', 'selected_category_id', 'house_area', 'gali_sector', 'city', 'pin_code',
        'address', 'account_holder_name', 'account_number', 'ifsc_code',
        'profile_image', 'adhaar_front_image', 'adhaar_back_image', 'labour_card',
        'provider_latitude', 'provider_longitude', 'provider_eloc', 'vehicle_availability', 'ur_user_status'
    ];
 
    $image_keys = [
        'profile_image', 'adhaar_front_image', 'adhaar_back_image', 'labour_card'
    ];
 
    $filtered_meta = [];
 
    foreach ($allowed_keys as $key) {
        if (isset($all_meta[$key])) {
            $value = maybe_unserialize($all_meta[$key][0]);
 
            // If it's an image key and the value is numeric (attachment ID), convert to URL
            if (in_array($key, $image_keys) && is_numeric($value)) {
                $image_url = wp_get_attachment_url($value);
                if ($image_url) {
                    $filtered_meta[$key] = $image_url;  // Store the image URL
                } else {
                    $filtered_meta[$key] = '';  // Image not found, return empty
                }
            } else {
                $filtered_meta[$key] = $value;  // Store other values directly
            }
        }
    }
 
    // Add basic user info
    $user = get_userdata($user_id);
    if ($user) {
        $filtered_meta['display_name'] = $user->display_name;
        $filtered_meta['user_email'] = $user->user_email;
    }
 
    return new \WP_REST_Response([
        'success' => true,
        'data' => $filtered_meta,
    ], 200);
}


// Update Service Provider Status pending approved and deny


	public static function update_service_provider_status($request) {
    $params = $request->get_json_params(); // Read raw JSON

    $user_id = $params['user_id'] ?? null;
    $status = $params['status'] ?? null;

    if (!$user_id || $status === null) {
        return new WP_Error('missing_fields', 'User ID and status are required.', ['status' => 400]);
    }

    // Ensure status is an integer
    $status = intval($status);

    // Valid numeric statuses
    $valid_statuses = [-1, 0, 1];

    if (!in_array($status, $valid_statuses)) {
        return new WP_Error('invalid_status', 'Invalid status value. Use -1 (denied), 0 (pending), or 1 (approved).', ['status' => 400]);
    }

    // Save numeric status directly
    update_user_meta($user_id, 'ur_user_status', $status);

    // Optional: readable status for response message
    $status_text = [
        -1 => 'denied',
         0 => 'pending',
         1 => 'approved'
    ][$status];

    // Get the FCM tokens from user meta (it may be an array)
    $fcm_tokens = get_user_meta($user_id, 'device_login_tokens', true);

    // Ensure $fcm_tokens is an array
    if (!is_array($fcm_tokens)) {
        $fcm_tokens = [];  // If not an array, make it an empty array
    }

    // If there are valid FCM tokens, proceed to send notifications
    if (!empty($fcm_tokens)) {
        // Message to send (default values)
        $message_title = '';
        $message_body = '';

        // Send the appropriate push notification based on the status
        if ($status === 1) {
            // Approved
            $message_title = "Account Approved";
            $message_body = "Your account has been approved.";
        } elseif ($status === -1) {
            // Denied
            $message_title = "Account Denied";
            $message_body = "Your account has been denied. Please contact support.";
        }

        // Only send a notification if we have a valid message title and body
        if ($message_title && $message_body) {
            foreach ($fcm_tokens as $fcm_token) {
                if (!empty($fcm_token)) {
                    // Send the notification to each valid FCM token
                   // self::sendPushNotification($fcm_token, $message_title, $message_body);
                }
            }
        }
    }

    return [
        'status' => 'success',
        'message' => 'Service provider status updated to "' . $status_text . '".'
    ];
}







		
		
public static function handle_approval_status() {
    $users = get_users([
        'role' => 'services_provider',
    ]);

    $result = [];

    foreach ($users as $user) {
        $raw_status = get_user_meta($user->ID, 'ur_user_status', true);

        // Convert status code to readable string
        switch ($raw_status) {
            case '1':
                $status = 'approved';
                break;
            case '0':
                $status = 'pending';
                break;
            case '-1':
                $status = 'denied';
                break;
            default:
                $status = 'pending'; // fallback if status is missing
        }

        $result[] = [
            'id' => $user->ID,
            'name' => $user->display_name,
            'email' => $user->user_email,
            'status' => $status,
        ];
    }

    // Sort result by ID descending
    usort($result, function($a, $b) {
        return $b['id'] <=> $a['id'];
    });

    return new \WP_REST_Response([
        'success' => true,
        'data' => $result,
    ], 200);
}



public static function edit_information_sewa_mitra($data) {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Headers: *");

    $user_id = get_current_user_id();
    $upload_errors = [];

    // ✅ Sanitize input data
    $display_name         = sanitize_text_field($data['display_name'] ?? '');
    $user_email           = sanitize_email($data['user_email'] ?? '');

    // ✅ Clean phone number (allow numbers and + only)
    $raw_phone_number     = $data['phone_number'] ?? '';
    $phone_number         = preg_replace('/[^0-9+]/', '', trim($raw_phone_number));

    // ✅ Validation (optional)
    if (!is_email($user_email)) {
        $upload_errors['user_email'] = 'Invalid email address.';
    }
	
    if (empty($phone_number)) {
        $upload_errors['phone_number'] = 'Phone number is required.';
    }

    // Return validation errors if any
    if (!empty($upload_errors)) {
        return [
            'success' => false,
            'message' => 'Validation failed.',
            'errors'  => $upload_errors,
        ];
    }

    // ✅ Update wp_users table
    wp_update_user([
		'ID'           => $user_id,
		'display_name' => $display_name,
		'user_email'   => $user_email,
	]);

//echo '<pre>';print_r($data['user_email']);die;
    // ✅ Update user meta fields
    $meta_fields = [
		
        'billing_email'         => sanitize_text_field($data['user_email'] ?? ''),
        'user_email'         => sanitize_text_field($data['user_email'] ?? ''),
        'phone'         => sanitize_text_field($data['phone_number'] ?? ''),
        'selected_category_id' => sanitize_text_field($data['selected_category_id'] ?? ''),
        'house_area'           => sanitize_text_field($data['house_area'] ?? ''),
        'gali_sector'          => sanitize_text_field($data['gali_sector'] ?? ''),
        'city'                 => sanitize_text_field($data['city'] ?? ''),
        'pin_code'             => sanitize_text_field($data['pin_code'] ?? ''),
        'account_holder_name'  => sanitize_text_field($data['account_name'] ?? ''),
        'account_number'       => sanitize_text_field($data['account_number'] ?? ''),
        'ifsc_code'            => sanitize_text_field($data['ifsc_code'] ?? ''),
    ];

    // Build combined address
    $address_parts = [
        sanitize_text_field($data['house_area'] ?? ''),
        sanitize_text_field($data['gali_sector'] ?? ''),
        sanitize_text_field($data['city'] ?? ''),
        sanitize_text_field($data['pin_code'] ?? '')
    ];
    $meta_fields['address'] = implode(', ', array_filter($address_parts));

    foreach ($meta_fields as $key => $value) {
        update_user_meta($user_id, $key, $value);
    }

    // ✅ Handle file uploads
    $upload_fields = ['profile_image', 'adhaar_front_image', 'adhaar_back_image', 'labour_card'];

    foreach ($upload_fields as $field) {
        if (!empty($_FILES[$field]['name'])) {
            $file = wp_handle_upload($_FILES[$field], ['test_form' => false]);

            if (isset($file['error'])) {
                $upload_errors[$field] = $file['error'];
            } else {
                update_user_meta($user_id, $field, esc_url_raw($file['url']));
            }
        }
    }

    // Return file upload errors if any
    if (!empty($upload_errors)) {
        return [
            'success' => false,
            'message' => 'File upload failed.',
            'errors'  => $upload_errors,
        ];
    }

    // ✅ All done
    return [
        'success' => true,
        'message' => 'User profile updated successfully.',
    ];
}




	
    // Sewa mitra Dashboard
	public static function sewa_mitra_dashboard($request) {
    global $wpdb;
    $user_id = $request['user_id'];
    
    if (!$user_id) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'User ID is required.'
        ], 400);
    }

    // Get staff ID
    $staff_id = $wpdb->get_var(
        $wpdb->prepare("SELECT id FROM {$wpdb->prefix}bookly_staff WHERE wp_user_id = %d", $user_id)
    );

    if (!$staff_id) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'No staff found for this user.'
        ], 404);
    }

    $today = date('Y-m-d');
    $now = current_time('mysql');

    // TODAY appointments
    $today_appointments = $wpdb->get_results(
        $wpdb->prepare("
            SELECT a.*, s.title AS service_name, p.post_title AS product_name
            FROM {$wpdb->prefix}bookly_appointments a
            LEFT JOIN {$wpdb->prefix}bookly_services s ON a.service_id = s.id
            LEFT JOIN {$wpdb->prefix}posts p ON s.wc_product_id = p.ID  -- Join using wc_product_id
            WHERE a.staff_id = %d AND DATE(a.start_date) = %s
            ORDER BY a.start_date ASC
        ", $staff_id, $today),
        ARRAY_A
    );

    // PAST appointments (history)
    $past_appointments = $wpdb->get_results(
        $wpdb->prepare("
            SELECT a.*, s.title AS service_name, p.post_title AS product_name
            FROM {$wpdb->prefix}bookly_appointments a
            LEFT JOIN {$wpdb->prefix}bookly_services s ON a.service_id = s.id
            LEFT JOIN {$wpdb->prefix}posts p ON s.wc_product_id = p.ID  -- Join using wc_product_id
            WHERE a.staff_id = %d AND a.start_date < %s
            ORDER BY a.start_date ASC
        ", $staff_id, $now),
        ARRAY_A
    );

    // UPCOMING appointments (future)
    $upcoming_appointments = $wpdb->get_results(
        $wpdb->prepare("
            SELECT a.*, s.title AS service_name, p.post_title AS product_name
            FROM {$wpdb->prefix}bookly_appointments a
            LEFT JOIN {$wpdb->prefix}bookly_services s ON a.service_id = s.id
            LEFT JOIN {$wpdb->prefix}posts p ON s.wc_product_id = p.ID  -- Join using wc_product_id
            WHERE a.staff_id = %d AND a.start_date > %s
            ORDER BY a.start_date ASC
        ", $staff_id, $now),
        ARRAY_A
    );

    return new WP_REST_Response([
        'success' => true,
        'today' => $today_appointments,
        'historical' => $past_appointments,
        'upcoming' => $upcoming_appointments
    ], 200);
}






       
    

	// Sewa mitra registration
	
  public function handle_sewamitra(WP_REST_Request $request) {
    $data = $request->get_params();
    $files = $request->get_file_params(); // Fetch uploaded files

    $response = HelperService::register_sewamitra($data, $files);

    if ($response instanceof \WP_REST_Response) {
        return $response;
    }

    return new \WP_REST_Response([
        'success' => false,
        'message' => 'Unexpected error.'
    ], 500);
}


public static function register_sewamitra($params, $files = []) {
    try {
        // Sanitize and assign the incoming parameters
        $first_name = sanitize_text_field($params['first_name'] ?? '');
        $last_name = sanitize_text_field($params['last_name'] ?? '');
        $name = trim("$first_name $last_name");

        $phone = sanitize_text_field($params['phone'] ?? '');
        if (empty($phone)) {
            error_log('Phone number is missing or empty.');
            return new WP_REST_Response(['status' => 'error', 'message' => 'Phone number is required.'], 400);
        }

        $email_input = sanitize_text_field($params['email'] ?? '');
        $email = is_email($email_input) ? sanitize_email($email_input) : sanitize_email($phone . '@chago.in');

        $password = sanitize_text_field($params['password'] ?? '');
        $confirm_password = sanitize_text_field($params['confirm_password'] ?? '');

        if ($password !== $confirm_password) {
            error_log('Passwords do not match.');
            return new WP_REST_Response(['status' => 'error', 'message' => 'Passwords do not match.'], 400);
        }

        if (username_exists($phone)) {
            error_log('Phone number already registered: ' . $phone);
            return new WP_REST_Response(['status' => 'error', 'message' => 'This mobile number is already registered.'], 400);
        }

        // Create the user
        $user_id = wp_create_user($phone, $password, $email);
        if (is_wp_error($user_id)) {
            error_log('Error creating user: ' . $user_id->get_error_message());
            return new WP_REST_Response([
                'status' => 'error',
                'message' => 'Error creating user: ' . $user_id->get_error_message(),
            ], 500);
        }

        wp_update_user([
            'ID' => $user_id,
            'display_name' => $name,
            'first_name' => $first_name,
            'last_name' => $last_name
        ]);
        
        // Log user update
        error_log("User updated successfully: User ID " . $user_id);

        // Get other parameters
        $token = $params['token'] ?? '';
        $service_provider_form = $params['service_provider_form'] ?? '';
        $house_area = sanitize_text_field($params['house_no'] ?? '');
        $gali_sector = sanitize_text_field($params['gali_sector'] ?? '');
        $city = sanitize_text_field($params['city'] ?? '');
        $pin_code = sanitize_text_field($params['pin_code'] ?? '');
        $vehicle_availability = sanitize_text_field($params['vehicle_availability'] ?? '');
        $full_address = trim("$house_area, $gali_sector, $city - $pin_code");

        $provider_latitude = is_numeric($params['provider_latitude'] ?? null) ? floatval($params['provider_latitude']) : 0;
        $provider_longitude = is_numeric($params['provider_longitude'] ?? null) ? floatval($params['provider_longitude']) : 0;
        $eloc = function_exists('get_eloc_from_address_mapmyindia') ? get_eloc_from_address_mapmyindia($full_address) : '';

        $account_number = sanitize_text_field($params['account_number'] ?? '');
        $account_name = sanitize_text_field($params['account_holder_name'] ?? '');
        $ifsc_code = sanitize_text_field($params['ifsc_code'] ?? '');
        $selected_category_id = sanitize_text_field($params['selected_category_id'] ?? '');

        // Save user meta
        update_user_meta($user_id, 'phone', $phone);
        update_user_meta($user_id, 'vehicle_availability', $vehicle_availability);
        update_user_meta($user_id, 'address', $full_address);
        update_user_meta($user_id, 'house_area', $house_area);
        update_user_meta($user_id, 'gali_sector', $gali_sector);
        update_user_meta($user_id, 'city', $city);
        update_user_meta($user_id, 'pincode', $pin_code);
        update_user_meta($user_id, 'ur_user_status', 0);
        update_user_meta($user_id, 'account_name', $account_name);
        update_user_meta($user_id, 'account_number', $account_number);
        update_user_meta($user_id, 'ifsc_code', $ifsc_code);
        update_user_meta($user_id, 'selected_category_id', $selected_category_id);
        update_user_meta($user_id, 'provider_latitude', $provider_latitude);
        update_user_meta($user_id, 'provider_longitude', $provider_longitude);
        update_user_meta($user_id, 'provider_eloc', $eloc);

        // Log user meta update
        error_log('User meta updated successfully for User ID: ' . $user_id);

        // Handle FCM token storage (save as an array)
        if (!empty($token)) {
            $existing_tokens = get_user_meta($user_id, 'device_login_tokens', true);

            // If no tokens exist, initialize as an empty array
            if (empty($existing_tokens)) {
                $existing_tokens = [];
            }

            // Ensure $token is an array
            if (!is_array($token)) {
                $token = (array) $token;
            }

            // Merge new tokens with the existing ones, avoiding duplicates
            $new_tokens = array_merge($existing_tokens, $token);
            $new_tokens = array_unique($new_tokens);

            // Update the user meta with the new tokens
            $updated = update_user_meta($user_id, 'device_login_tokens', $new_tokens);

            if ($updated) {
                error_log('Device tokens updated successfully for user ID: ' . $user_id);
            } else {
                error_log('Failed to update device tokens for user ID: ' . $user_id);
            }
        } else {
            error_log('No FCM tokens provided for user ID: ' . $user_id);
        }

        // Save other meta data
        update_user_meta($user_id, 'service_provider_form', $service_provider_form);

        // Handle file uploads and store attachment ID
        $upload_fields = [
            'profile_image' => 'profile_image',
            'adhaar_front_image' => 'aadhaar_front',
            'adhaar_back_image' => 'aadhaar_back',
            'labour_card' => 'labour_card',
        ];

        foreach ($upload_fields as $field => $meta_key) {
            if (!empty($files[$field])) {
                $attach_id = self::upload_file_image($files[$field], $user_id, $meta_key);
                if ($attach_id) {
                    update_user_meta($user_id, $meta_key, $attach_id);
                }
            }
        }

        // Log file upload handling
        error_log('File uploads processed for user ID: ' . $user_id);

        // Assign role to the user
        $user = new WP_User($user_id);
        $user->set_role('services_provider');

        // Log user role assignment
        error_log('Role assigned to user ID: ' . $user_id . ' - services_provider');

        // Retrieve all admins
        $args_admins = [
            'role' => 'administrator',
            'fields' => ['ID', 'user_email'] // Get user ID and email
        ];

        $admins = get_users($args_admins);

        // Loop through all admins to send push notifications
        foreach ($admins as $admin) {
            // Retrieve FCM tokens for the admin
            $fcm_tokens = get_user_meta($admin->ID, 'device_login_tokens', true);

            // Log the FCM tokens for debugging
            error_log('Admin FCM tokens for Admin ID ' . $admin->ID . ': ' . print_r($fcm_tokens, true));

            // Check if FCM tokens are valid (non-empty array)
            if (is_array($fcm_tokens) && !empty($fcm_tokens)) {
                try {
                    // Prepare the custom data to send with the push notification
                    $customData = [
                        'customData' => 'value',  // Default custom data
                        'type' => 'service_provider',  // Example static type
                        'url' => '/admin/service_provider_approval', // Add the URL field
                    ];

                    // Send push notification to all FCM tokens in the array
                    self::sendPushNotification($fcm_tokens, 
                        "A new service provider has filled the service provider form and is waiting for your approval.", 
                        "Please review the service provider's form.", 
                        $customData
                    );

                    // Log success message after sending the notification
                    error_log('Push notification successfully sent to admin ID: ' . $admin->ID . ' with tokens: ' . implode(', ', $fcm_tokens));

                } catch (Exception $e) {
                    // Log any errors encountered while sending the notification
                    error_log('Failed to send push notification to admin ID: ' . $admin->ID . '. Error: ' . $e->getMessage());
                }
            } else {
                // Log if no valid tokens found for the admin
                error_log('No valid FCM tokens found for admin ID: ' . $admin->ID);
            }
        }

        // Return success response
        return new WP_REST_Response([
            'status' => 'success',
            'message' => 'User registered successfully. Pending approval.',
            'user_id' => $user_id
        ], 200);

    } catch (Exception $e) {
        // Log any unexpected errors that occur during the process
        error_log('Error in register_sewamitra: ' . $e->getMessage());
        return new WP_REST_Response([
            'status' => 'error',
            'message' => 'Internal server error: ' . $e->getMessage()
        ], 500);
    }
}






public static function upload_file_image($file, $user_id, $meta_key) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';
    require_once ABSPATH . 'wp-admin/includes/image.php';

    $upload_overrides = ['test_form' => false];

    $uploaded_file = wp_handle_upload($file, $upload_overrides);
 // error_log('Upload result for file: ' . print_r($uploaded_file, true));
    if (!empty($uploaded_file['file']) && !isset($uploaded_file['error'])) {
        $file_path = $uploaded_file['file'];

        $attachment = [
            'post_mime_type' => $uploaded_file['type'],
            'post_title'     => sanitize_file_name($file_path),
            'post_content'   => '',
            'post_status'    => 'inherit'
        ];

        $attach_id = wp_insert_attachment($attachment, $file_path);

        $attach_data = wp_generate_attachment_metadata($attach_id, $file_path);
        wp_update_attachment_metadata($attach_id, $attach_data);

        return $attach_id;
    }

    return false;
}




  
	
	
	// Signup 
	// Validate email and username
	public static function signup_user($data) {
    $email = sanitize_email($data['email']);
    $password = $data['password'];
    $firstname = sanitize_text_field($data['firstname']);
    $lastname = sanitize_text_field($data['lastname']);
    $country = sanitize_text_field($data['country']);
    $dob = sanitize_text_field($data['dob']);
    $Gender = sanitize_text_field($data['Gender']);
    $city = sanitize_text_field($data['city']);
    $pincode = sanitize_text_field($data['pincode']);
    $phone = sanitize_text_field($data['phone']);
    $state = sanitize_text_field($data['state']);
    $role = sanitize_text_field($data['role']);
    $token = $data['token']; // This could be an array of tokens

    if (!is_email($email)) {
        return [
            'success' => false,
            'message' => 'Invalid Email',
        ];
    }

    if (email_exists($email)) {
        return [
            'success' => false,
            'message' => 'Email already exists',
        ];
    }

    // Create user
    $user_id = wp_create_user($email, $password, $email);
    if (is_wp_error($user_id)) {
        return [
            'success' => false,
            'message' => 'User Registration Failed',
        ];
    }

    // Set the user role (default 'subscriber' or custom role)
    $user = get_userdata($user_id);
    $user->set_role('subscriber'); // Set to 'subscriber' or another role

    // Update user metadata
    wp_update_user([
        'ID' => $user_id,
        'first_name' => $firstname,
        'last_name' => $lastname,
    ]);
    
    update_user_meta($user_id, 'user_registration_country_1623050729', $country);
    update_user_meta($user_id, 'user_registration_date_box_1623051693', $dob);
    update_user_meta($user_id, 'user_registration_input_box_1623050696', $city);
    update_user_meta($user_id, 'user_registration_input_box_1623050879', $pincode);
    update_user_meta($user_id, 'user_registration_input_box_1623050759', $state);
    update_user_meta($user_id, 'user_registration_phone', $phone);
    
    // Check if token is an array
    if (is_array($token)) {
        // If it's an array, we can store it directly as an array
        update_user_meta($user_id, 'device_login_tokens', $token);
    } else {
        // If it's a single token, convert it into an array
        update_user_meta($user_id, 'device_login_tokens', [$token]);
    }

    // Generate fake token (you can integrate JWT or any other token generation logic here)
    $generated_token = 'faketoken';
    
    // Return the response with the user data
    $data = [
        'token' => $generated_token,
        'user_id' => $user_id,
    ];
    
    return [
        'success' => true,
        'message' => 'SignUp Successful',
        'data' => $data,
    ];
}

    public static function upload_base64_image($base64_string, $user_id, $meta_key) {
        if (empty($base64_string)) return false;

        preg_match('/data:image\/(.*?);base64,(.*)/', $base64_string, $matches);
        if (!isset($matches[2])) return false;

        $ext = $matches[1];
        $img_data = base64_decode($matches[2]);
        $filename = $meta_key . '_' . $user_id . '.' . $ext;

        $upload = wp_upload_bits($filename, null, $img_data);
        if (!empty($upload['error'])) return false;

        update_user_meta($user_id, $meta_key, $upload['url']);

        return true;
    }

	
	public static function forget_password($identify){
		// Validate user input
		//error_log('heeeee');error_log(print_r($identify, true));
		$user_input = sanitize_text_field($identify);
		//error_log('hewwwweeee');error_log(print_r($user_input, true));
				if (empty($user_input)) {
					return [
				'success' => false,
				'message' => 'Empty mail',
				];
				}

				// Find the user by email or username
				if (is_email($user_input)) {
					$user = get_user_by('email', $user_input);
				} else {
					$user = get_user_by('login', $user_input);
				}

                if ( is_wp_error( !$user ) ) {
            	return [
				'success' => false,
				'message' => 'No such email or username found',
				];
		
        }
				// Generate a password reset token
				$reset_key = get_password_reset_key($user);
				
                if ( is_wp_error( $reset_key ) ) {
        
					// Extract all error messages
					$errors = $reset_key->errors;

					// Initialize a variable to store the first error message
					$error_message = 'Unable to reset password.';

					// If there are errors, fetch the first message dynamically
					if (!empty($errors)) {
						foreach ($errors as $error_type => $messages) {
							if (!empty($messages) && is_array($messages)) {
								$error_message = $messages[0]; // Get the first error message
								$clean_error_message = strip_tags($error_message);
								break; // Exit the loop after fetching the first error
							}
						}
					}

					return [
						'success' => false,
						'message' => $clean_error_message,
					];
				}
				// Create the reset URL
				$reset_url = add_query_arg([
					'key' => $reset_key,
					'login' => rawurlencode($user->user_login),
				], wp_lostpassword_url());

				// Send the email
				$subject = 'Password Reset Request';
				$message = "Hello,\n\n";
				$message .= "You requested a password reset. Click the link below to reset your password:\n\n";
				$message .= $reset_url . "\n\n";
				$message .= "If you didn't request this, please ignore this email.\n";

				$mail_sent = wp_mail($user->user_email, $subject, $message);

				// if (!$mail_sent) {
				// 	return new WP_Error('email_failed', 'Failed to send password reset email.', ['status' => 500]);
				// }
				if ( is_wp_error( !$mail_sent ) ) {
            	return [
				'success' => false,
				'message' => 'Failed to send password reset email.',
				];
            }
            
        return [
			'success'      => true,
			'message'      => 'Password reset email sent successfully.',
			];
	}

	public static function get_user_profile($user_id){
		
		if (!$user_id) {
					return [
						'success'=> false,
						'message'=> 'User not logged in.'
						];
				}

				// Get user data
				$user = get_userdata($user_id);

				// Prepare the response
				$data = [
					'id' => $user->ID,
					'username' => $user->user_login,
					'email' => $user->user_email,
					'display_name' => $user->display_name,
					'first_name' => get_user_meta($user_id, 'first_name', true),
					'last_name' => get_user_meta($user_id, 'last_name', true),
					'role' => $user->roles,
				];

				return [
					'success' => true,
					'message'=> 'User profile details.',
					'data' => $data
					];
	}

	public static function get_catogories(){
		$args = [
			'taxonomy'   => 'product_cat',
			'hide_empty' => false,
			'parent'     => 0,
			'exclude'    => array(23),
		];

		// Fetch categories
		$categories = get_terms($args);
			$category_data = [];
	 
		// Loop through the categories and collect the required data
		foreach ($categories as $category) {
			// Store term_id, name, and slug in the category_data array
			$category_icon_image_id = get_term_meta($category->term_id,'category_icon_image',true);
			
			$image_id = get_term_meta($category->term_id, 'thumbnail_id', true); // 'thumbnail_id' is commonly used for category images
			$image_url = $image_id ? wp_get_attachment_url($image_id) : '';
			$category_data[] = [
				'term_id' => $category->term_id,
				'name'    => $category->name,
				'slug'    => $category->slug,
				'image_url' => $image_url,
				'category_icon_image_url' => $category_icon_image_id
			];
		}

		// Return the collected data in the response
		return [
				'success'=> true,
				'message'=> 'Categories',
				'data'=> $category_data ];
	}

	public static function update_order_booking($request) {
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Headers: *");

	
		$razorpay_key = defined('WC_RAZORPAY_KEY') ? WC_RAZORPAY_KEY : '';
		$razorpay_secret = defined('WC_RAZORPAY_SECRET') ? WC_RAZORPAY_SECRET : '';


		if (empty($razorpay_key) || empty($razorpay_secret)) {
			return [
				'success' => false,
				'message' => 'Razorpay API credentials not found.'
			];
		}
		
		$url = 'https://api.razorpay.com/v1/orders';
		$postData = $request->get_json_params();


		$headers = array(
			'Content-Type: application/json',
			'Authorization: Basic ' . base64_encode($razorpay_key . ':' . $razorpay_secret)
		);
		$transaction_id = $postData['transaction_id'] ?? null;
		$payment_id = $postData['payment_id'] ?? null;
		$product_id = $postData['line_items'][0]['product_id'] ?? null;

		if (!empty($response) && isset($response['id'])) {
			return [
				'success' => true,
				'message' => 'Successfully Ordered',
				'data'    => $response
			];
		} else {
			return [
				'success' => false,
				'message' => 'Error in payment processing'
			];
		}
	}


	public static function get_subcategories($request){
    $parent_id = $request->get_param('id');
    
    $args = array(
        'parent'   => $parent_id,
        'taxonomy' => 'product_cat',
        'orderby'  => 'name',      
        'order'    => 'ASC',
        'hide_empty' => false
    );

    $subcategories = get_terms($args);

    if (is_wp_error($subcategories)) {
        return ['success' => false, 'message' => $subcategories->get_error_message()];
    }

    if (!empty($subcategories)) {
        $subcategory_data = [];

        foreach ($subcategories as $subcategory) {
            $image_id = get_term_meta($subcategory->term_id, 'thumbnail_id', true);
            $image_url = $image_id ? wp_get_attachment_url($image_id) : '';

            $subcategory_data[] = [
                'term_id'   => $subcategory->term_id,
                'name'      => $subcategory->name,
                'slug'      => $subcategory->slug,
                'image_url' => $image_url,
            ];
        }

        return [
            'success' => true,
            'message' => 'Subcategories found.',
            'type'    => 'subcategories',
            'data'    => $subcategory_data
        ];
    }

    // 🔁 No subcategories? Fetch products in this category instead.
    $product_args = [
        'post_type'      => 'product',
        'posts_per_page' => -1,
        'post_status'    => 'publish',
        'tax_query'      => [
            [
                'taxonomy' => 'product_cat',
                'field'    => 'term_id',
                'terms'    => $parent_id,
            ],
        ],
    ];

    $products = new WP_Query($product_args);

    if ($products->have_posts()) {
        $product_data = [];

        while ($products->have_posts()) {
            $products->the_post();
            $product_id = get_the_ID();
            $product = wc_get_product($product_id);

            $product_data[] = [
                'id'         => $product_id,
                'title'      => get_the_title(),
                'price'      => $product->get_price_html(),
                'image_url'  => get_the_post_thumbnail_url($product_id, 'full'),
                'author'     => get_the_author(),
                'area'       => get_post_meta($product_id, '_product_area', true),
                'permalink'  => get_permalink($product_id),
            ];
        }
        wp_reset_postdata();

        return [
            'success' => true,
            'message' => 'No subcategories. Products found.',
            'type'    => 'products',
            'data'    => $product_data
        ];
    }

    // ❌ No subcategories and no products
    return [
        'success' => false,
        'message' => 'No subcategories or products found.'
    ];
}


	public static function get_product_details($subcategory_id) {
		// Ensure WooCommerce is loaded
		if (!class_exists('WC_Product')) {
			return new WP_REST_Response(['error' => 'WooCommerce not loaded'], 400);
		}

		// Query products based on subcategory
		$query = new \WC_Product_Query([
			'tax_query' => [
				[
					'taxonomy' => 'product_cat', 
					'field'    => 'term_id',
					'terms'    => $subcategory_id,
				],
			],
			'limit' => 1, 
		]);

		$products = $query->get_products();
		$product = reset($products); // Get the first product

		// If no product is found, use product ID 1582 as default
		if (!$product) {
			$product = wc_get_product(1582);
		}

		if (!$product) {
			return [
				'success' => false,
				'message' => 'No products found',
			];
		}

		// Prepare product data
		$data = [
			'id'               => $product->get_id(),
			'name'             => $product->get_name(),
			'description'      => $product->get_description(),
			'short_description'=> $product->get_short_description(),
			'price'            => $product->get_price(),
			'regular_price'    => $product->get_regular_price(),
			'sale_price'       => $product->get_sale_price(),
			'stock_status'     => $product->get_stock_status(),
			'categories'       => wp_get_post_terms($product->get_id(), 'product_cat', ['fields' => 'names']),
			'image'            => wp_get_attachment_url($product->get_image_id()), // Main product image
			'gallery'          => array_map('wp_get_attachment_url', $product->get_gallery_image_ids()), // Gallery images
			'permalink'        => get_permalink($product->get_id()),
		];

		return [
			'success' => true,
			'message' => 'Product fetched successfully',
			'data'    => $data,
		];
	}


public static function get_product_detail_page($product_id) {
    // Ensure WooCommerce is loaded
    if (!class_exists('WC_Product')) {
        return new WP_REST_Response(['error' => 'WooCommerce not loaded'], 400);
    }
	
    // If no product is found, use product ID 1582 as default
    $product = wc_get_product($product_id);
	
    if (empty($product)) {
		return ;
    }

    // Prepare product data
    $data = [
        'id'               => $product->get_id(),
        'name'             => $product->get_name(),
        'description'      => $product->get_description(),
        'short_description'=> $product->get_short_description(),
        'price'            => $product->get_price(),
        'regular_price'    => $product->get_regular_price(),
        'sale_price'       => $product->get_sale_price(),
        'stock_status'     => $product->get_stock_status(),
        'categories'       => wp_get_post_terms($product->get_id(), 'product_cat', ['fields' => 'names']),
        'image'            => wp_get_attachment_url($product->get_image_id()), // Main product image
        'gallery'          => array_map('wp_get_attachment_url', $product->get_gallery_image_ids()), // Gallery images
        'permalink'        => get_permalink($product->get_id()),
    ];

    return [
        'success' => true,
        'message' => 'Product fetched successfully',
        'data'    => $data
    ];
}

public static function most_booked_services(){
    
	global $wpdb;
    $limit = 5;
    $excluded_category_id = 107;

	// Prepare SQL query to fetch products excluding those with 0 bookings and a specific category
	$query = $wpdb->prepare("
		SELECT p.ID, p.post_title, pm.meta_value AS sales
		FROM {$wpdb->posts} p
		LEFT JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id
		LEFT JOIN {$wpdb->term_relationships} tr ON p.ID = tr.object_id
		LEFT JOIN {$wpdb->term_taxonomy} tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
		WHERE p.post_type = 'product'
		AND p.post_status = 'publish'
		AND pm.meta_key = 'total_sales'
		AND CAST(pm.meta_value AS UNSIGNED) > 0  -- Exclude products with zero bookings
		AND (
			tt.taxonomy != 'product_cat' 
			OR tt.term_id != %d
		)
		GROUP BY p.ID
		ORDER BY CAST(pm.meta_value AS UNSIGNED) DESC
		LIMIT %d
	", $excluded_category_id, $limit);

	$results = $wpdb->get_results($query);
	$service_data = [];

	foreach ($results as $product) {
		$wc_product = wc_get_product($product->ID); // Get WooCommerce product object

		$service_data[] = [
			'id'             => $product->ID,
			'name'           => $product->post_title,
			'total_bookings' => (int) $product->sales, // Correctly reference the sales column
			'thumbnail' => get_the_post_thumbnail_url($product->ID, 'full') ?: get_template_directory_uri() . '/images/default.png',
			'price'          => $wc_product ? $wc_product->get_price() : null,
			'sale_price'     => $wc_product ? $wc_product->get_sale_price() : null,
			'regular_price'  => $wc_product ? $wc_product->get_regular_price() : null,
			'short_description' => $wc_product ? $wc_product->get_short_description(): null,
		];
	   
	}
	if(!$service_data){
         return [
                'success' => false,
                'message' => 'Unable to fetch services',
            ];
    }
    else{
        return [
                'success' => true,
                'message' => 'Most booked services',
                'data' => $service_data
            ];
    }
}

	public static function bookingstatusUpdate($request) {
		$order_id = $request['order_id'];
		// $order_id = 123; // Replace with the actual order ID
		$consumer_key = 'ck_84708ff3c3edf9f59ec3c3cceb4efccd1087c840'; 
		$consumer_secret = 'cs_518345b4fbe3338ea6d12270040590f1302abeae'; 

		$api_url = "https://chago.in/wp-json/wc/v3/orders/$order_id?consumer_key=$consumer_key&consumer_secret=$consumer_secret";

		$data = [
			'status' => 'processing'
		];
		
		// echo base64_encode("$consumer_key:$consumer_secret");die;
		$response = wp_remote_post($api_url, [
			'method'    => 'PUT',
			'body'      => json_encode($data),
			'headers'   => [
				'Authorization' => 'Basic ' . base64_encode("$consumer_key:$consumer_secret"),
				'Content-Type'  => 'application/json',
			],
		]);
		// echo "<pre>";print_r($response);
		if (is_wp_error($response)) {
			error_log('API Error: ' . $response->get_error_message());
			return new \WP_REST_Response([
				'success' => false,
				'message' => 'Error in updating Order status.',
				'data'=>array()
			]);
		} else {
			error_log('Order updated successfully: ' . wp_remote_retrieve_body($response));
			return new \WP_REST_Response([
				'success' => true,
				'message' => 'Order status updated successfully.',
				'data'=>json_decode(wp_remote_retrieve_body($response))
			]);
		}
	}
	public static function get_user_bookings_data($user_id) {
		
		global $wpdb;

		// Step 1: Get the customer_id from wp_bookly_customers based on wp_user_id
		$customer_id = $wpdb->get_var(
			$wpdb->prepare("
				SELECT id 
				FROM {$wpdb->prefix}bookly_customers 
				WHERE wp_user_id = %d
			", $user_id)
		);

		if ($customer_id) {
			// Step 2: Fetch detailed data by joining the two tables
			$query = "
				SELECT 
					app.id AS appointment_id,
					app.start_date,
					app.created_at,
					cust_app.status
				FROM {$wpdb->prefix}bookly_appointments AS app
				INNER JOIN {$wpdb->prefix}bookly_customer_appointments AS cust_app
					ON app.id = cust_app.appointment_id
				WHERE cust_app.customer_id = %d
				ORDER BY app.id DESC
			";

			// Execute the query and fetch results
			$appointments = $wpdb->get_results($wpdb->prepare($query, $customer_id), ARRAY_A);

			// Check if there are appointments
			if (!empty($appointments)) {
				$appointments_data = [];

				// Process and format the results
				foreach ($appointments as $appointment) {
					$appointments_data[] = [
						'appointment_id' => $appointment['appointment_id'],
						'start_date'     => $appointment['start_date'],
						'created_at'     => $appointment['created_at'],
						'status'         => $appointment['status'],
					];
				}

				// Return success response with data
				return [
					'success' => true,
					'message' => $appointments_data,
				];
			} else {
				// No appointments found
				return [
					'success' => false,
					'message' => 'No bookings yet',
				];
			}
		} else {
			// No customer found
			return [
				'success' => false,
				'message' => 'No customer found',
			];
		}
	}

    public static function change_user_password($request){
            $user_id = $request['user_id'];
			$current_password = $request['current_password'];
			$new_password = $request['new_password'];

			// Validate the input
			if (empty($user_id) || empty($current_password) || empty($new_password)) {
			    return [
            'success' => false,
            'message' => 'Missing required parameters.',
        ];
			}

			// Get the user data
			$user = get_userdata($user_id);
			if (!$user) {
			    return [
            'success' => false,
            'message' => 'User not found.',
        ];
			}

			// Verify the current password
			if (!wp_check_password($current_password, $user->user_pass, $user->ID)) {
			    return [
            'success' => false,
            'message' => 'Current password is incorrect.',
        ];
			}

			// Check if the new password is strong enough
			if (strlen($new_password) < 8) {
			    return [
            'success' => false,
            'message' => 'New password must be at least 8 characters long.',
        ];
			}

			// Update the password
			wp_set_password($new_password, $user->ID);

			// Return success response
			return [
            'success' => true,
            'message' => 'Password updated successfully.',
        ];
}

public static function user_profile_update($data, $user_id){
    // print_r($data);die;
        
        $firstname = sanitize_text_field($data['firstname'] ?? '');
        $lastname = sanitize_text_field($data['lastname'] ?? '');
        $country = sanitize_text_field($data['country'] ?? '');
        $dob = sanitize_text_field($data['dob'] ?? '');
        $gender = sanitize_text_field($data['Gender'] ?? '');
        $city = sanitize_text_field($data['city'] ?? '');
        $pincode = sanitize_text_field($data['pincode'] ?? '');
        $phone = sanitize_text_field($data['phone'] ?? '');
        $state = sanitize_text_field($data['state'] ?? '');
        $display_name = sanitize_text_field($data['display_name'] ?? '');
        //$role = sanitize_text_field($data['role'] ?? '');

        // if (!is_wp_error($user_id)) {
        //     $user = get_userdata($user_id);
        //     // $user->set_role('subscriber'); // Uncomment to set the role
        // }
        
        // Prepare data for wp_update_user
        $user_update_data = [
            'ID' => $user_id,
            'first_name' => $firstname,
            'last_name' => $lastname,
            'display_name' => $display_name,
        ];
        
        // Filter out empty values for wp_update_user
        $user_update_data = array_filter($user_update_data);
        
        // Update user data
        if (!empty($user_update_data)) {
            wp_update_user($user_update_data);
        }
        
        // Prepare meta fields for update
        $meta_fields = [
            'user_registration_country_1623050729' => $country,
            'user_registration_date_box_1623051693' => $dob,
            'user_registration_input_box_1623050696' => $city,
            'user_registration_input_box_1623050879' => $pincode,
            'user_registration_input_box_1623050759' => $state,
            'user_registration_phone' => $phone,
        ];
        
        // Filter out empty values and update meta
        foreach ($meta_fields as $meta_key => $value) {
            if (!empty($value)) {
                update_user_meta($user_id, $meta_key, $value);
            }
        }
        return [
            'success' => true,
            'message' => 'User profile updated.'
            ];

}

public static function delete_user_account($user_id, $password) {
    global $wpdb;

    // Validate input
    if (empty($user_id) || empty($password)) {
        return [
            'success' => false,
            'message' => 'User ID and password are required to delete the account.'
        ];
    }
    $user = get_userdata($user_id);
    if (!$user) {
        return [
            'success' => false,
            'message' => 'User account not found.'
        ];
    }
        // Fetch the user's hashed password from the database
        $table_name = $wpdb->prefix . 'users';
        $query = $wpdb->prepare("SELECT user_pass FROM {$table_name} WHERE ID = %d", $user_id);
        $storedPasswordHash = $wpdb->get_var($query);
        // Verify the password
        if (!wp_check_password($password, $storedPasswordHash, $user_id)) {
            return [
                'success' => false,
                'message' => 'Incorrect password. Account deletion failed.'
            ];
        }

        // Delete the user account
        $delete_result = wp_delete_user($user_id);

        // Check if the deletion was successful
        if ($delete_result) {
            return [
                'success' => true,
                'message' => 'User account has been successfully deleted.'
            ];
        } else {
            return [
                'success' => false,
                'message' => 'Failed to delete the user account. Please try again later.'
            ];
        }
    
        return [
            'success' => false,
            'message' => 'An error occurred'
        ];
}

public static function add_to_wishlist($user_id, $product_id){
    
    if ( empty( $user_id ) || empty( $product_id ) ) {
        return array(
            'success' => false,
            'message' => 'Invalid user ID or product ID.',
        );
    }
    $user_id =intval($user_id);
    $product_id = intval($product_id);
    $user = get_userdata($user_id);
    if (!$user) {
        return [
            'success' => false,
            'message' => 'User account not found.'
        ];
    }
    //Ensure the product exists
    $product = wc_get_product( $product_id );
    if ( ! $product ) {
        return array(
            'success' => false,
            'message' => 'Service does not exist.',
        );
    }
    
// 	$user_id = $args[ 'user_id' ];
    // Check if the user has a default wishlist
    $wishlist = YITH_WCWL_Wishlist_Factory::generate_default_wishlist($user_id);
    if(!$wishlist){
  
    try {
        $wishlist = new YITH_WCWL_Wishlist();
        $wishlist->set_user_id( $user_id );
        $wishlist->set_name( 'Default Wishlist' );
        //$wishlist->set_visibility( 1 ); // Default visibility (public)

        // Save the wishlist
        $wishlist->save();
        // Return the ID of the newly created wishlist
    } catch ( Exception $e ) {
        // Handle any errors during wishlist creation
        error_log( 'Error creating wishlist: ' . $e->getMessage() );
        return false; // Return false if there was an error
    }
    // phpcs:enable

}
    
  $wishlist_items = $wishlist->get_items();

    foreach ( $wishlist_items as $item ) {
        if ( $item->get_product_id() === $product_id ) {
            return array(
                'success' => false,
                'message' => 'Service is already in the wishlist.',
            );
        }
    }

     // Create a new wishlist item
    $item = new YITH_WCWL_Wishlist_Item();
    $item->set_product_id( $product_id );
    $item->set_quantity( 1 );
    $item->set_wishlist_id( $wishlist->get_id() );
    $item->set_user_id( $wishlist->get_user_id() );
    $item->set_date_added( time() );

    // Add the item to the wishlist
    try {
        $wishlist->add_item( $item );
        $wishlist->save(); // Save the wishlist after adding the item

        return array(
            'success' => true,
            'message' => 'Service successfully added to the wishlist.',
        );
    } catch ( Exception $e ) {
        error_log( 'Wishlist add_item error: ' . $e->getMessage() );
        return array(
            'success' => false,
            'message' => 'An error occurred while adding the Service to the wishlist.',
        );
        }
    }

    public static function remove_from_wishlist($user_id, $product_id) {
        if (empty($user_id) || empty($product_id)) {
            return array(
                'success' => false,
                'message' => 'Invalid user ID or product ID.',
            );
        }
    
        $user_id = intval($user_id);
        $product_id = intval($product_id);
        $user = get_userdata($user_id);
    
        if (!$user) {
            return array(
                'success' => false,
                'message' => 'User account not found.',
            );
        }
    
        // Ensure the product exists
        $product = wc_get_product($product_id);
        if (!$product) {
            return array(
                'success' => false,
                'message' => 'Service does not exist.',
            );
        }
    
        // Get the default wishlist for the user
        $wishlist = YITH_WCWL_Wishlist_Factory::generate_default_wishlist($user_id);
        if (!$wishlist) {
            return array(
                'success' => false,
                'message' => 'Wishlist not found for the user.',
            );
        }
    
        // Get the wishlist items
        $wishlist_items = $wishlist->get_items();
    
        // Find and remove the item if it exists
        foreach ($wishlist_items as $item) {
            if ($item->get_product_id() === $product_id) {
                try {
                    $wishlist->remove_item($item->get_id());
                    $wishlist->save(); // Save the wishlist after removing the item
    
                    return array(
                        'success' => true,
                        'message' => 'Service successfully removed from the wishlist.',
                    );
                } catch (Exception $e) {
                    error_log('Wishlist remove_item error: ' . $e->getMessage());
                    return array(
                        'success' => false,
                        'message' => 'An error occurred while removing the Service from the wishlist.',
                    );
                }
            }
        }
    
        return array(
            'success' => false,
            'message' => 'Service not found in the wishlist.',
        );
    }
    
public static function get_reviews($product_id) {
    
    $ReviewArr = array(
            'post_type'      => 'wpcr3_review',
            'post_status'    => 'publish',
            'meta_query'     => array(
                array(
                    'key'     => 'wpcr3_review_post',
                    'value'   => $product_id,
                    'compare' => '='
                )
            ),
            'posts_per_page' => -1,
        );

        $GetReviews = new \WP_Query($ReviewArr);
    // print_r($GetReviews);die;
        if (!$GetReviews->have_posts()) {
             return array(
                'success' => true,
                'message' => 'No reviews found for the given Product ID.',
            );
        }
    
        $response = array();
    
        while ($GetReviews->have_posts()) {
            $GetReviews->the_post();
            $reviewer_name = get_post_meta(get_the_ID(), 'wpcr3_review_name', true);
            $reviewer_rating = get_post_meta(get_the_ID(), 'wpcr3_review_rating', true);
            $reviewer_image = get_field('reviewer_image');
    
            $response[] = array(
                'id'          => get_the_ID(),
                'title'       => get_the_title(),
                'content'     => get_the_content(),
                'reviewer'    => $reviewer_name,
                'rating'      => $reviewer_rating,
                'image'       => $reviewer_image ? esc_url($reviewer_image) : get_template_directory_uri() . '/images/user-profile-icon-vector-avatar.webp',
                'date'        => get_the_date(),
            );
        }
    
        wp_reset_postdata();
    
        return array(
                'success' => true,
                'message' => 'Reviews retrieved.',
                'data'  => $response,
            );
    
    }
    
	public static function postRequest($url, $postData, $header)
	{
		$curl = curl_init();

		curl_setopt_array($curl, array(
			CURLOPT_URL => $url,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_ENCODING => '',
			CURLOPT_MAXREDIRS => 10,
			CURLOPT_TIMEOUT => 30, // Set timeout to prevent long execution
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST => 'POST',
			CURLOPT_POSTFIELDS => is_array($postData) ? json_encode($postData) : $postData, // Convert array to JSON if needed
			CURLOPT_HTTPHEADER => $header,
		));

		$response = curl_exec($curl);
		$httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

		if (curl_errno($curl)) {
			$error_msg = curl_error($curl);
			curl_close($curl);
			return json_encode(["success" => false, "message" => "cURL Error: $error_msg"]);
		}

		curl_close($curl);

		return $response;
	}

  public static function create_woo_commerce_order($request) {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Headers: *");

    $url = "https://chago.in/wp-json/wc/v3/orders";
    $postData = $request->get_json_params();

    // Extract data from the request
    $product_id = $postData['line_items'][0]['product_id']; 
    $email = $postData['customer_email']; 
    $date_time = $postData['date'];
    $name = $postData['billing']['first_name'] . ' ' . $postData['billing']['last_name']; 
    $consumer_key = defined('WC_CONSUMER_KEY') ? WC_CONSUMER_KEY : 'ck_84708ff3c3edf9f59ec3c3cceb4efccd1087c840';
    $consumer_secret = defined('WC_CONSUMER_SECRET') ? WC_CONSUMER_SECRET : 'cs_518345b4fbe3338ea6d12270040590f1302abeae';
    $auth = base64_encode("$consumer_key:$consumer_secret");

    $headers = [
        "Authorization: Basic $auth",
        "Content-Type: application/json"
    ];

    // Create WooCommerce order
    $response = self::postRequest($url, $postData, $headers);

    // Retrieve service based on the product ID
    $service = self::get_service_by_product($product_id);
	
    $service_id = $service->id;
   $orderData = json_decode($response, true);

		if (json_last_error() !== JSON_ERROR_NONE || !isset($orderData['id'])) {
			error_log("Invalid JSON or missing order ID in response: " . $response);
			return [
				'success' => false,
				'message' => 'Failed to create WooCommerce order. Server response was invalid.',
				'raw_response' => $response
			];
		}

//print_r($orderData);die;
    // Create the appointment in Bookly
    $appointment = self::bookly_create_appointment($service_id, $name, $email, $date_time, $orderData['id']);
// print_r($orderData);die;
    $appointmentData = $appointment->data;
    $appointmentData['order_id'] = $orderData['id'];

    // Store the appointment ID as meta data for the WooCommerce order
    update_post_meta($orderData['id'], '_bookly_appointment_id', $appointmentData['appointment_id']);

    // Send notifications to customer and staff
    self::send_appointment_notifications($email, $appointmentData['appointment_id'], $service_id, $date_time);

    // Return the response
    if ($appointmentData) {
        return [
            'success' => true,
            'message' => 'Appointment successfully added.',
            'data' => $appointmentData,
        ];
    }
}


public static function send_appointment_notifications($customer_email, $appointment_id, $service_id, $appointment_time) {
    global $wpdb;

    // Retrieve customer details
    $user = get_user_by('email', $customer_email);
    if (!$user) {
        error_log("No customer found with email: {$customer_email}");
        return;
    }
    
    // Retrieve the array of FCM tokens for the customer
    $customer_fcm_tokens = get_user_meta($user->ID, 'device_login_tokens', true);
    if (empty($customer_fcm_tokens) || !is_array($customer_fcm_tokens)) {
        error_log("No valid FCM tokens found for customer: {$customer_email}");
        return;
    }

    // Retrieve the staff associated with this service
    $staff = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT b.full_name, b.email, b.phone, b.attachment_id 
             FROM {$wpdb->prefix}bookly_staff b
             JOIN {$wpdb->prefix}bookly_services s ON s.id = b.id
             WHERE s.id = %d", $service_id
        )
    );

    if (!$staff) {
        error_log("No staff found for service ID: {$service_id}");
        return;
    }

		  // Retrieve staff FCM token
		$staff_user = get_user_by('email', $staff->email);
		$staff_fcm = $staff_user ? get_user_meta($staff_user->ID, 'device_login_tokens', true) : null;

		// Compose messages for customer and staff
		$customer_msg = "✅ Your appointment for {$service_id} has been confirmed on {$appointment_time} with {$staff->full_name}.";
		$staff_msg = "📢 You have been assigned a new appointment for {$service_id} on {$appointment_time}. Customer: {$customer_email}.";

		// Default custom data for staff notifications
		$customData = array_merge([
			'customData' => 'value',  // Default custom data
			'type' => 'order_booking',  // Example static type
			'url' => '/provider/order', // Add the URL field
		], []); // Merge any additional custom data if needed

		// Send push notification to all customer devices if FCM tokens exist
		if ($customer_fcm_tokens) {
			$helperService = new RestMyApis\Services\HelperService();

			// Loop through all customer tokens and send the notification
			foreach ($customer_fcm_tokens as $token) {
				if (!empty($token)) {
					$helperService->sendPushNotification([$token], $customer_msg);
					error_log("FCM sent to customer: {$customer_email}, token: {$token}");
				}
			}
		} else {
			error_log("No customer FCM tokens found for email: {$customer_email}");
		}

		// Send push notification to staff if FCM token exists and add custom data
		if ($staff_fcm) {
			$helperService = new RestMyApis\Services\HelperService();
			
			// Send the staff notification with custom data
			$helperService->sendPushNotification([$staff_fcm], $staff_msg, $customData);
			error_log("FCM sent to staff: {$staff->email}");
		} else {
			error_log("No staff FCM token found for email: {$staff->email}");
		}
	}



	public static function bookly_create_appointment($service_id, $name, $email, $date_time, $woo_order_id) {
		global $wpdb;

		// Format date and time
		$datetime = new \DateTime($date_time);
		$booking_date = $datetime->format('Y-m-d');
		$start_time = $datetime->format('H:i:s');
		$end_time = (new \DateTime($date_time))->modify('+1 hour')->format('H:i:s');

		// Get staff assigned to service
		$staff_id = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT staff_id FROM {$wpdb->prefix}bookly_staff_services WHERE service_id = %d LIMIT 1",
				$service_id
			)
		);
		if (!$staff_id) {
			return [
				'success' => false,
				'message' => 'No staff assigned to this service.',
				'error' => 'Missing staff assignment.'
			];
		}


		// Get customer by email
		$customer_id = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}bookly_customers WHERE email = %s LIMIT 1",
				$email
			)
		);

		$appointment_data = [
			'staff_id' => $staff_id,
			'service_id' => $service_id,
			'booking_date' => $booking_date,
			'start_time' => $start_time,
			'end_time' => $end_time,
			'customer_id' => $customer_id,

			'customer_name' => $name,
			'customer_email' => $email,
			'customer_phone' => '', // Optional but important if customer needs to be created

			'order_id' => $woo_order_id,
			'status' => 'approved',
			'payment_status' => 'paid'
		];

		$response = self::bookly_appointment($appointment_data);
		$response_data = json_decode(json_encode($response), true);

		if (isset($response_data['error'])) {
			return [
				'success' => false,
				'message' => 'Failed to create appointment.',
				'error' => $response_data['error'],
				'order_id' => $response_data['order_id'] ?? null,
			];
		}

		return [
			'success' => true,
			'message' => 'Appointment successfully added.',
			'data' => $response_data,
		];
	}



	public static function bookly_appointment($data) {
    global $wpdb;
    
    // Bookly Tables
    $appointments_table = $wpdb->prefix . 'bookly_appointments';
    $customers_table = $wpdb->prefix . 'bookly_customers';
    $customers_appointments_table = $wpdb->prefix . 'bookly_customer_appointments';
    $orders_table = $wpdb->prefix . 'bookly_orders';

    // Check if the required data is passed in the request
    if (empty($data['staff_id']) || empty($data['service_id']) || empty($data['customer_id']) || empty($data['booking_date']) || empty($data['start_time']) || empty($data['end_time'])) {
        return new \WP_REST_Response([
            'error' => 'Missing required fields: staff_id, service_id, customer_id, booking_date, start_time, or end_time.'
        ], 400);
    }

    // Generate a new token
    $token = bin2hex(random_bytes(16));

    // Insert the token into the orders table
    $wpdb->insert($orders_table, ['token' => $token]);

    // Get the newly created order ID
    $order_id = $wpdb->insert_id;

    // Dynamic data from the request
    $staff_id = $data['staff_id']; // Staff ID (dynamic)
    $service_id = $data['service_id']; // Service ID (dynamic)
    $customer_id = $data['customer_id']; // Existing customer ID (dynamic)
    $booking_date = $data['booking_date']; // Booking date (dynamic)
    $start_time = $data['start_time']; // Start time (dynamic)
    $end_time = $data['end_time']; // End time (dynamic)
    $status = isset($data['status']) ? $data['status'] : 'approved'; // Status of the booking (default: 'approved')
    $payment_status = isset($data['payment_status']) ? $data['payment_status'] : 'paid'; // Payment status (default: 'paid')
    

    // Step 1: Insert Appointment (if necessary)
    $wpdb->insert($appointments_table, [
        'staff_id' => $staff_id,
        'service_id' => $service_id,
        'start_date' => "{$booking_date} {$start_time}",
        'end_date' => "{$booking_date} {$end_time}",
        
    ]);

    $appointment_id = $wpdb->insert_id;

    // Step 2: Insert Customer (if customer does not exist)
    if (!$customer_id) {
        if (empty($data['customer_name']) || empty($data['customer_email']) || empty($data['customer_phone'])) {
            return new \WP_REST_Response([
                'error' => 'Missing customer details: customer_name, customer_email, or customer_phone.'
            ], 400);
        }

        // Insert new customer if not provided
        $wpdb->insert($customers_table, [
            'full_name' => $data['customer_name'],
            'email' => $data['customer_email'],
            'phone' => $data['customer_phone'],
        ]);
        $customer_id = $wpdb->insert_id;
    }

    // Step 3: Link Customer to Appointment
    $wpdb->insert($customers_appointments_table, [
        'appointment_id' => $appointment_id,
        'customer_id' => $customer_id,
        'status' => $status,
        'number_of_persons' => isset($data['number_of_persons']) ? $data['number_of_persons'] : 1, // Default number of persons: 1
        'custom_fields' => isset($data['custom_fields']) ? $data['custom_fields'] : '',
        'extras' => isset($data['extras']) ? $data['extras'] : '',
        'compound_service_id' => isset($data['compound_service_id']) ? $data['compound_service_id'] : null,
        'compound_token' => isset($data['compound_token']) ? $data['compound_token'] : null,
        'order_id' => $order_id,
    ]);

    return new \WP_REST_Response([
        'appointment_id' => $appointment_id,
        'order_id' => $order_id
    ]);
}

	
	
	public static function bookly_available_slots($request) {
		global $wpdb;
		
		$product_id = isset($request["product_id"]) ? (int) $request["product_id"] : null;
		$date = isset($request["date"]) ? $request["date"] : null;

		if (!$product_id || !$date) {
			return rest_ensure_response(new \WP_Error('missing_parameters', 'Product ID and Date are required.', ['status' => 400]));
		}

		try {
			
			$service = self::get_service_by_product($product_id);
			// print_r($service);die;
			$service_id = $service->id; // Duration in seconds
			$duration = (int) $service->duration; // Duration in seconds

			// Get Staff ID assigned to this service
			$staff_services_table = $wpdb->prefix . 'bookly_staff_services';
			
			$staff_query = $wpdb->prepare(
				"SELECT staff_id FROM $staff_services_table WHERE service_id = %d LIMIT 1",
				$service_id
			); 
			$staff_id = $wpdb->get_var($staff_query);
			// echo "saini";echo $staff_id;die;
			if (!$staff_id) {
				return rest_ensure_response(new \WP_Error('staff_not_found', 'No staff found for the provided service.', ['status' => 404]));
			}

			// Define Slot Time Range (8 AM to 6 PM)
			$start_time = strtotime($date . ' 08:00:00'); // Business start time
			$end_time = strtotime($date . ' 18:00:00');   // Business end time

			// Get current time in WordPress timezone
			$current_time = current_time('timestamp');
			$today = date('Y-m-d', $current_time);

			// If the selected date is today, update start_time to the next available slot
			if ($date === $today) {
				$rounded_current_time = ceil($current_time / $duration) * $duration;
				if ($rounded_current_time > $start_time) {
					$start_time = $rounded_current_time;
				}
			}

			// Fetch Existing Appointments from bookly_appointments table
			$appointments_table = $wpdb->prefix . 'bookly_appointments';
			$appointments_query = $wpdb->prepare(
				"SELECT UNIX_TIMESTAMP(start_date) as start_time, UNIX_TIMESTAMP(end_date) as end_time 
				 FROM $appointments_table 
				 WHERE service_id = %d 
				 AND staff_id = %d 
				 AND DATE(start_date) = %s",
				$service_id,
				$staff_id,
				$date
			); 
			$appointments = $wpdb->get_results($appointments_query);
			// echo "<pre>";print_r($appointments);die;
			// Convert booked appointments into an array of blocked slots
			$booked_slots = [];
			foreach ($appointments as $appointment) {
				$start_slot = (int) $appointment->start_time;
				$end_slot = (int) $appointment->end_time;

				while ($start_slot < $end_slot) {
					$booked_slots[] = $start_slot;  // Store each booked timestamp
					$start_slot += $duration;
				}
			}

			// Generate Available Slots based on service duration
			$available_slots = [];
			$current_slot_time = $start_time;

			while ($current_slot_time + $duration <= $end_time) {
				$next_time = $current_slot_time + $duration;
				$is_available = true;

				// Check if the current slot is inside any booked slots
				foreach ($booked_slots as $booked_time) {
					if (
						($current_slot_time >= $booked_time && $current_slot_time < ($booked_time + $duration)) || 
						($next_time > $booked_time && $next_time <= ($booked_time + $duration))
					) {
						$is_available = false;
						break;
					}
				}

				if ($is_available) {
					$available_slots[] = date('H:i', $current_slot_time);
				}

				$current_slot_time = $next_time;
			}

			return rest_ensure_response([
				'success' => true,
				'message' => 'Available slots retrieved successfully.',
				'available_slots' => $available_slots,
			]);

		} catch (Exception $e) {
			return rest_ensure_response(new \WP_Error('error_fetching_slots', $e->getMessage(), ['status' => 500]));
		}

	}
	public static function generate_dynamic_form_and_csrf() {
		if (!session_id()) {
			session_start();
		}

		$form_id = wp_generate_uuid4(); // Generate a unique form ID
		$secret_key = wp_salt(); // Get a secret key for security
		$csrf_token = hash_hmac('sha256', $form_id . time(), $secret_key); // Generate CSRF token

		// Store them in session
		$_SESSION['csrf_tokens'][$form_id] = $csrf_token;

		return ['form_id' => $form_id, 'csrf_token' => $csrf_token];
	}

	public static function get_service_by_product($product_id)
	{
		global $wpdb;

		// Get Service ID and Duration from bookly_services
		$services_table = $wpdb->prefix . 'bookly_services';
		$service_query = $wpdb->prepare(
			"SELECT id, duration FROM $services_table WHERE wc_product_id = %d LIMIT 1",
			$product_id
		);
		$service = $wpdb->get_row($service_query);
		
		if (!$service) {
			return rest_ensure_response(new \WP_Error('service_not_found', 'No matching service found for the provided product ID.', ['status' => 404]));
		}

		// $service_id = $service->id;		
		return $service;
	}
	public static function get_bookly_available_slots($service_id, $staff_id, $date) {
				global $wpdb;

		// Get the service duration
		$service = Service::find($service_id); 
		//echo"<pre>";print_r;($service);die;
		if (!$service) {
			throw new Exception('Service not found.');
		}
		$service_duration = $service->getDuration();

		// Get the staff working hours for the given date
		$staff = Bookly\Lib\Entities\Staff::find($staff_id);
		if (!$staff) {
			throw new Exception('Staff not found.');
		}
		$working_hours = $staff->getWorkingHoursForDate($date);
		if (!$working_hours) {
			throw new Exception('Working hours not found.');
		}

		// Get all booked appointments for the selected date
		$booked_slots = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT start_time, end_time FROM wp_bookly_appointments 
				WHERE staff_id = %d AND DATE(start_time) = %s",
				$staff_id,
				$date
			),
			ARRAY_A
		);

		// Generate available slots based on staff working hours and service duration
		$available_slots = [];
		$start_time = strtotime($working_hours['start']);
		$end_time = strtotime($working_hours['end']);

		// Generate time slots
		while ($start_time + $service_duration <= $end_time) {
			$slot_start = date('H:i', $start_time);
			$slot_end = date('H:i', $start_time + $service_duration);

			// Check if the slot overlaps with any booked appointments
			$is_available = true;
			foreach ($booked_slots as $appointment) {
				$appointment_start = strtotime($appointment['start_time']);
				$appointment_end = strtotime($appointment['end_time']);
				if (($start_time < $appointment_end) && ($start_time + $service_duration > $appointment_start)) {
					$is_available = false;
					break;
				}
			}

			if ($is_available) {
				$available_slots[] = ['start' => $slot_start, 'end' => $slot_end];
			}

			// Move to the next slot
			$start_time += $service_duration;
		}

		return $available_slots;

	}
	
	public static function sub_categories($request) {
    $category_id = $request['subcat_id'];

    if (empty($category_id) || !is_numeric($category_id)) {
        return new \WP_REST_Response([
            'success' => false,
            'message' => 'Valid Category ID is required.',
        ], 400);
    }

    $term = get_term($category_id, 'product_cat');
    if (is_wp_error($term) || !$term) {
        return new \WP_REST_Response([
            'success' => false,
            'message' => 'Category not found.',
        ], 404);
    }

    $parent_category_name = 'No Parent Category Found';
    if ($term->parent) {
        $parent = get_term($term->parent, 'product_cat');
        if (!is_wp_error($parent)) {
            $parent_category_name = $parent->name;
        }
    }

    // First try to get subcategories
    $args = [
        'taxonomy'   => 'product_cat',
        'orderby'    => 'name',
        'hide_empty' => false,
        'parent'     => $category_id,
    ];
    $subcategories = get_terms($args);

    if (!empty($subcategories)) {
        $subcategory_data = [];
        foreach ($subcategories as $subcategory) {
            $subcategory_image_id = get_term_meta($subcategory->term_id, 'thumbnail_id', true);
            $subcategory_image_url = $subcategory_image_id
                ? wp_get_attachment_url($subcategory_image_id)
                : 'path/to/your/default-image.jpg';

            $service_page_link = get_permalink(get_page_by_path('service')) . '?subcat_id=' . $subcategory->term_id;

            $subcategory_data[] = [
                'id' => $subcategory->term_id,
                'name' => $subcategory->name,
                'slug' => $subcategory->slug,
                'description' => $subcategory->description,
                'image_url' => $subcategory_image_url,
                'service_page_link' => $service_page_link,
            ];
        }

        return new \WP_REST_Response([
            'success' => true,
            'type' => 'subcategories',
            'message' => 'Subcategories fetched successfully.',
            'parent_category' => $parent_category_name,
            'data' => $subcategory_data,
        ], 200);
    }

    // If no subcategories, try to fetch products
    $product_args = [
        'post_type' => 'product',
        'post_status' => 'publish',
        'posts_per_page' => -1,
        'tax_query' => [
            [
                'taxonomy' => 'product_cat',
                'field'    => 'term_id',
                'terms'    => $category_id,
            ],
        ],
    ];

    $products = get_posts($product_args);
    if (!empty($products)) {
        $product_data = [];
        foreach ($products as $product_post) {
            $product_id = $product_post->ID;
            $product = wc_get_product($product_id);

            $product_data[] = [
                'id' => $product_id,
                'name' => $product->get_name(),
                'price' => $product->get_price(),
                'image' => wp_get_attachment_url($product->get_image_id()),
                'link' => get_permalink($product_id),
            ];
        }

        return new \WP_REST_Response([
            'success' => true,
            'type' => 'products',
            'message' => 'Products found in category.',
            'parent_category' => $parent_category_name,
            'data' => $product_data,
        ], 200);
    }

    // Nothing found
    return new \WP_REST_Response([
        'success' => false,
        'message' => 'No subcategories or products found in this category.',
        'parent_category' => $parent_category_name,
    ], 404);
}






	public static function child_sub_categories($request) {
			$subcategory_id = $request['subcat_id'];

			if ($subcategory_id) {
				// Fetch services related to the specified subcategory
				$args = array(
					'post_type' => 'product', // Assuming services are WooCommerce products
					'tax_query' => array(
						array(
							'taxonomy' => 'product_cat',
							'field'    => 'term_id',
							'terms'    => $subcategory_id,
						),
					),
				);
		
			   $services = new \WP_Query($args);
				if ($services->have_posts()) {
					$products_data = []; // Array to store products' data

					// Loop through each service (product)
					while ($services->have_posts()) {
						$services->the_post();

						// Get product details
						$service_image = get_the_post_thumbnail_url(get_the_ID(), 'full');
						$price = get_post_meta(get_the_ID(), '_price', true);
						$product_id = get_the_ID();
						$product_author = get_the_author();
						$product_area = get_post_meta($product_id, '_product_area', true);

						// Collect product data into an array
						$products_data[] = array(
							'product_id'     => $product_id,
							'product_title'  => get_the_title(),
							'product_link'   => get_the_permalink(),
							'service_image'  => $service_image,
							'price'          => $price,
							'product_author' => $product_author,
							'product_area'   => $product_area
						);
					}

					// Reset post data after custom query
					wp_reset_postdata();

					// Return the list of services (products) in the response
					return new \WP_REST_Response(
						array(
							'success' => true,
							'message' => 'Services fetched successfully.',
							'data'    => $products_data // Return the collected product data
						),
						200
					);
				} else {
					// No services found for this subcategory
					return new \WP_REST_Response(
						array(
							'success' => false,
							'message' => 'No services found for this subcategory.',
						),
						404
					);
				}
			} else {
				// No subcategory ID provided
				return new \WP_REST_Response(
					array(
						'success' => false,
						'message' => 'Subcategory ID is required.',
					),
					400
				);
			}
		}


		public static function recent_orders($user_id) {
			global $wpdb;
			$customer_id = 123; // Replace with the actual customer ID
			$orders = wc_get_orders([
				'customer_id' => $user_id,
				'limit'       => -1, // Retrieve all orders for the user
			]);
			
			if (!get_user_by('ID', $user_id)) {
				return new WP_Error('user_not_found', 'User not found', ['status' => 404]);
			}

			// Check if WooCommerce is active
			if (!class_exists('WooCommerce')) {
				return new WP_Error('woocommerce_inactive', 'WooCommerce is not active', ['status' => 500]);
			}
			// Get orders with multiple statuses
			$args = [
					'customer' => $user_id, // Correct parameter for fetching customer orders
					'orderby'  => 'date',
					'order'    => 'DESC'
				];


			if (empty($orders)) {
				return [
					'success' => false,
					'message' => 'No orders found',
				];
			}

			$order_list = [];

			foreach ($orders as $order) {
				$order_data = [
					'order_id'     => $order->get_id(),
					'date_created' => $order->get_date_created()->date('Y-m-d H:i:s'),
					'status'       => $order->get_status(),
					'total'        => $order->get_total(),
					'currency'     => $order->get_currency(),
					'products'     => self::get_order_items($order), // Get all products
				];

				$order_list[] = $order_data;
			}

			return [
				'success' => true,
				'orders'  => $order_list
			];
	}


		private static function get_order_items($order) {
			$items = [];

			foreach ($order->get_items() as $item_id => $item) {
				$product = $item->get_product();

				if ($product) {
					$items[] = [
						'product_id'   => $product->get_id(),
						'product_name' => $item->get_name(),
						'quantity'     => $item->get_quantity(),
						'subtotal'     => $item->get_subtotal(),
						'total'        => $item->get_total(),
						'image'        => wp_get_attachment_url($product->get_image_id()), // Product image
						'permalink'    => get_permalink($product->get_id()), // Product URL
					];
				}
			}
			return $items;
		}



	public static function search_box($request) {
    $search_query = sanitize_text_field($request->get_param('search')); // Get search term
    
    if (!$search_query) {
        return new \WP_REST_Response([
            'success' => false,
            'message' => 'Search term is required.',
        ], 400);
    }

    $results = [];

    // Step 1: Search for matching product categories
    $categories = get_terms([
        'taxonomy'   => 'product_cat',
        'name__like' => $search_query,
        'hide_empty' => false,
    ]);

    if (!empty($categories)) {
        foreach ($categories as $category) {
            $thumbnail_id = get_term_meta($category->term_id, 'thumbnail_id', true);
            $image_url = $thumbnail_id ? wp_get_attachment_url($thumbnail_id) : wc_placeholder_img_src();
            $category_url = get_term_link($category);
            
            $results[] = [
                'id'            => $category->term_id,
                'product_name'  => $category->name,
                'product_image' => $image_url,
                'product_link'  => esc_url($category_url),
                'type'          => 'category'
            ];
        }
    }

    // Step 2: Search for products matching the search term
    $args = [
        'post_type'      => 'product',
        'posts_per_page' => -1,
        's'             => $search_query,
    ];

    $query = new \WP_Query($args);

    if ($query->have_posts()) {
        while ($query->have_posts()) {
            $query->the_post();
            
            $product_id = get_the_ID();
            $product = wc_get_product($product_id);
            if (!$product) continue;

            $service_image = get_the_post_thumbnail_url($product_id, 'full');
            $price = $product->get_price_html();
            $product_author = get_the_author();
            $product_area = get_post_meta($product_id, '_product_area', true);
            $product_link = get_permalink($product_id);
            
            $results[] = [
                'product_id'     => $product_id,
                'product_title'  => get_the_title(),
                'product_link'   => esc_url($product_link),
                'service_image'  => $service_image,
                'price'          => $price,
                'product_author' => $product_author,
                'product_area'   => $product_area,
                'type'           => 'product'
            ];
        }
        wp_reset_postdata();
    }

    if (empty($results)) {
        return new \WP_REST_Response([
            'success' => false,
            'message' => 'No services or categories found for this search query.',
        ], 404);
    }

    return new \WP_REST_Response([
        'success' => true,
        'message' => 'Results fetched successfully.',
        'data'    => $results
    ], 200);
}
public static function save_fcm_token($request){
	$user_id = $request->get_param('user_id');
    $device_token = sanitize_text_field($request->get_param('device_token'));
	//echo "$user_id";die;

    if (!$user_id || !$device_token) {
        return new WP_REST_Response(['status' => 'error', 'message' => 'Missing parameters'], 400);
    }

    update_user_meta($user_id, 'fcm_device_token', $device_token);

    return new WP_REST_Response(['status' => 'success'], 200);

	
}

	public static function write_a_review($request) {
        
        $review_title = $request->get_param('review_title');
        $review_content = $request->get_param('review_content');
        $review_ip = $request->get_param('review_ip');
        $product_id = $request->get_param('product_id');
        $reviewer_name = $request->get_param('review_name');
        $reviewer_email = $request->get_param('reviewer_email');
        $review_rating = $request->get_param('review_rating');
    
        // Check if all required fields are provided
        if (empty($product_id) || empty($reviewer_email) || empty($review_content) || empty($reviewer_name) || empty($review_rating)) {
            return array(
                'success' => false,
                'message' => 'Missing required fields.',
            );
        }
    
        // Validate rating
        if ($review_rating < 1 || $review_rating > 5) {
            return array(
                'success' => false,
                'message' => 'Rating must be between 1 and 5.',
            );
        }
    
        // Prepare data for saving
        $review_data = [
            'post_type'    => 'wpcr3_review',
            'post_title'   => $review_title,
            'post_content' => $review_content,
            'post_status'  => 'publish',
            'meta_input'   => [
                'wpcr3_review_ip'       => $review_ip,
                'wpcr3_review_post'     => $product_id,
                'wpcr3_review_name'     => $reviewer_name,
                'wpcr3_review_email'    => $reviewer_email,
                'wpcr3_review_rating'   => $review_rating,
                'wpcr3_review_title'    => $review_title,
                'wpcr3_review_website'=> '',
            ],
        ];
    
        // Insert the review as a new post
        $review_id = wp_insert_post($review_data);
    
        if ($review_id) {
            return array(
                'success' => true,
                'message' => 'Review submitted successfully.',
            );
        }
        return array(
                'success' => false,
                'message' => 'Error submitting review.',
            );
    }



public static function handle_to_let_service_registration($request) {
    // Require user to be logged in
    $user_id = get_current_user_id();
    if (!$user_id) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'You must be logged in to submit a property.',
        ], 401);
    }

    // Required field validation
    $required_fields = [
        'owner_name',
        'price',
        'contact',
        'location',
        'description'
    ];

    $missing = [];
    foreach ($required_fields as $field) {
        if (empty($request->get_param($field))) {
            $missing[] = $field;
        }
    }

    if (!empty($missing)) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'Missing required fields: ' . implode(', ', $missing)
        ], 400);
    }

    if (!is_numeric($request->get_param('price'))) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'Price must be a valid number.'
        ], 400);
    }

    // Category IDs (Usage > Type > Subtypes)
    $cat_ids = [];
    if ($request->get_param('usage')) {
        $cat_ids[] = intval($request->get_param('usage'));
    }
    if ($request->get_param('property_type')) {
        $cat_ids[] = intval($request->get_param('property_type'));
    }
    for ($i = 1; $i <= 3; $i++) {
        $param_name = 'sub_type_level_' . $i;
        if ($request->get_param($param_name)) {
            $cat_ids[] = intval($request->get_param($param_name));
        }
    }

    // Create product post
    $product_data = [
        'post_title'   => sanitize_text_field($request->get_param('owner_name')),
        'post_type'    => 'product',
        'post_status'  => 'pending',
        'post_author'  => $user_id,
        'post_content' => sanitize_textarea_field($request->get_param('description')),
    ];

    $product_id = wp_insert_post($product_data);

    if (is_wp_error($product_id)) {
        return new WP_REST_Response([
            'success' => false,
            'message' => 'Failed to create property.',
            'error'   => $product_id->get_error_message()
        ], 500);
    }

    // Save meta fields
    $meta_fields = [
        '_regular_price' => 'price',
        '_price' => 'price',
        'contact' => 'contact',
        'location' => 'location',
        'area' => 'area',
        'furnishing' => 'furnishing',
        'lease_type' => 'lease_type',
        'cabins' => 'cabins',
        'open_space_option' => 'open_space_option',
        'prefered_floor' => 'prefered_floor',
        'seating_capacity' => 'seating_capacity',
        'caretaker' => 'caretaker',
        'caretaker_name' => 'caretaker_name',
        'caretaker_phone' => 'caretaker_phone',
        'footfall' => 'footfall',
        'visibility' => 'visibility',
        'ceilingHeight' => 'ceilingHeight',
        'loadingFacilities' => 'loadingFacilities',
        'bhk' => 'bhk',
        'floor' => 'floor',
        'house-parking' => 'house-parking',
        'sharing-type' => 'sharing-type',
        'gender' => 'gender',
        'food-included' => 'food-included',
        'room-set' => 'room-set',
        'bathroom' => 'bathroom',
        'full_address' => 'full_address',
    ];

    foreach ($meta_fields as $meta_key => $param_name) {
        $value = $request->get_param($param_name);
        if (!empty($value)) {
            update_post_meta($product_id, $meta_key, sanitize_text_field($value));
        }
    }

    // Save amenities (array)
    $amenities = $request->get_param('amenities');
    if (!empty($amenities)) {
        if (!is_array($amenities)) {
            $amenities = explode(',', sanitize_text_field($amenities));
        }
        update_post_meta($product_id, 'amenities', array_map('sanitize_text_field', $amenities));
    }

    // Set product categories
    if (!empty($cat_ids)) {
        wp_set_object_terms($product_id, $cat_ids, 'product_cat');
    }

    // Handle uploaded images (file upload or base64)
    if ($request->get_file_params() && isset($_FILES['images']['name'][0])) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';
        require_once ABSPATH . 'wp-admin/includes/media.php';

        $files = $request->get_file_params();
        $gallery_ids = [];

        if (isset($files['images']['name']) && is_array($files['images']['name'])) {
            $count = count($files['images']['name']);
            for ($i = 0; $i < $count; $i++) {
                $file = [
                    'name'     => $files['images']['name'][$i],
                    'type'     => $files['images']['type'][$i],
                    'tmp_name' => $files['images']['tmp_name'][$i],
                    'error'    => $files['images']['error'][$i],
                    'size'     => $files['images']['size'][$i],
                ];

                if ($file['error'] === 0 && !empty($file['tmp_name'])) {
                    $upload_id = media_handle_sideload($file, $product_id);
                    if (!is_wp_error($upload_id)) {
                        $gallery_ids[] = $upload_id;
                    } else {
                        return new WP_REST_Response(['error' => $upload_id->get_error_message()], 500);
                    }
                }
            }

            if (!empty($gallery_ids)) {
                set_post_thumbnail($product_id, $gallery_ids[0]);
                if (count($gallery_ids) > 1) {
                    $gallery = $gallery_ids;
                    array_shift($gallery); // Remove featured
                    update_post_meta($product_id, '_product_image_gallery', implode(',', $gallery));
                }
            }
        }
    }

    return new WP_REST_Response([
        'success'     => true,
        'message'     => 'Property submitted successfully.',
        'product_id'  => $product_id
    ], 200);
}



	public static function convertToNumber($val) {
		
    $val = str_replace(['₹', '+', ' '], '', $val);
    if (strpos($val, 'K') !== false) {
        return (int) $val * 1000;
    } elseif (strpos($val, 'L') !== false) {
        return (int) $val * 100000;
    }
    return (int) $val;
}

public static function single_property($request) {
    $product_id = isset($request['id']) ? intval($request['id']) : 0;

    if (!$product_id) {
        return [
            'success' => false,
            'message' => 'Product ID is missing or invalid.'
        ];
    }

    $product = wc_get_product($product_id);

    if (!$product) {
        return [
            'success' => false,
            'message' => 'Product not found.'
        ];
    }

    // Get product data
    $product_data = [
        'id'          => $product_id,
        'name'        => $product->get_name(),
        'price_html'  => $product->get_price_html(),
        'price'       => $product->get_price(),
        'description' => $product->get_description(),
        'image'       => get_the_post_thumbnail_url($product_id, 'large'),
    ];

    return [
        'success' => true,
        'message' => 'Product retrieved successfully.',
        'data'    => $product_data
    ];
}

public static function handle_property_results($request) {
	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers: *");
    // Enable error logging
    $params = $request->get_params();

    // Sanitize parameters
    $city             = sanitize_text_field($params['city'] ?? '');
    $area             = sanitize_text_field($params['area'] ?? '');
    $subcat_id        = intval($params['subcat_id'] ?? '');
    $budget           = sanitize_text_field($params['budget'] ?? '');
    $bhk              = sanitize_text_field($params['bhk'] ?? '');
    $furnishing       = sanitize_text_field($params['furnishing'] ?? '');
    $floor            = sanitize_text_field($params['floor'] ?? '');
    $cabins           = sanitize_text_field($params['cabins'] ?? '');
    $open_space       = sanitize_text_field($params['open_space_option'] ?? '');
    $prefered_floor   = sanitize_text_field($params['prefered_floor'] ?? '');
    $seating_capacity = sanitize_text_field($params['seating_capacity'] ?? '');
    $contact          = sanitize_text_field($params['contact'] ?? '');
    $lease_type       = sanitize_text_field($params['lease_type'] ?? '');
    $footfall         = sanitize_text_field($params['footfall'] ?? '');
    $visibility       = sanitize_text_field($params['visibility'] ?? '');
    $ceilingHeight    = sanitize_text_field($params['ceilingHeight'] ?? '');
    $loadingFacilities= sanitize_text_field($params['loadingFacilities'] ?? '');
    $house_parking    = sanitize_text_field($params['house-parking'] ?? '');
    $sharing_type     = sanitize_text_field($params['sharing-type'] ?? '');
    $gender           = sanitize_text_field($params['gender'] ?? '');
    $food_included    = sanitize_text_field($params['food-included'] ?? '');
    $bathroom         = sanitize_text_field($params['bathroom'] ?? '');
    $area_sqft        = sanitize_text_field($params['area_sqft_'] ?? '');
    $amenities        = isset($params['amenities']) ? array_map('sanitize_text_field', (array) $params['amenities']) : [];

    $location = trim($city . ' - ' . $area, ' -');


	
	
    // Budget range
    $min = 0;
    $max = PHP_INT_MAX;

   //for price
	if ($budget) {
		$budget = str_replace(['–', '—', ' '], ['-', '-', ''], $budget);
		if (strpos($budget, 'Under') !== false) {
			preg_match('/₹?(\d+)([KL]?)/', $budget, $matches);
			$max = self::convertToNumber($matches[1] . $matches[2]);
		} elseif (strpos($budget, '+') !== false) {
			preg_match('/₹?(\d+)([KL]?)/', $budget, $matches);
			$min = self::convertToNumber($matches[1] . $matches[2]);
		} elseif (strpos($budget, '-') !== false) {
			preg_match('/₹?(\d+)([KL]?)\-₹?(\d+)([KL]?)/', $budget, $matches);
			$min = self::convertToNumber($matches[1] . $matches[2]);
			$max = self::convertToNumber($matches[3] . $matches[4]);
		}
	}
		// Setup WP_Query args
		$args = [
			'post_type'      => 'product',
			'posts_per_page' => -1,
			'tax_query'      => [],
			'meta_query'     => ['relation' => 'OR'],
		];

		if (!empty($subcat_id)) {
		$args['tax_query'][] = [
			'taxonomy'         => 'product_cat',
			'field'            => 'term_id',
			'terms'            => $subcat_id,
			'include_children' => true,
		];
	}
	   if (!empty($area_sqft_)) {
		$args['meta_query'][] = [
			'key'     => 'area',
			'value'   => $area_sqft_,
			'compare' => '='
		];
	}

	if (!empty($bhk)) {
		$args['meta_query'][] = [
			'key'     => 'bhk',
			'value'   => $bhk,
			'compare' => '='
		];
	}
	
	if ($budget) {
		$args['meta_query'] = [
			[
				'key' => '_price', 
				'value' => [$min, $max],
				'type' => 'NUMERIC',
				'compare' => 'BETWEEN',
			],
		];
	}

	if (!empty($furnishing)) {
		$args['meta_query'][] = [
			'key'     => 'furnishing',
			'value'   => $furnishing,
			'compare' => '='
		];
	}

	if (!empty($floor)) {
		$args['meta_query'][] = [
			'key'     => 'floor',
			'value'   => $floor,
			'compare' => '='
		];
	}

	// Additional fields to filter by (from the update_post_meta fields)
	if (!empty($contact)) {
		$args['meta_query'][] = [
			'key'     => 'contact',
			'value'   => $contact,
			'compare' => '='
		];
	}

	if (!empty($location)) {
		$args['meta_query'][] = [
			'key'     => 'location',
			'value'   => $location,
			'compare' => '='
		];
	}

	if (!empty($lease_type)) {
		$args['meta_query'][] = [
			'key'     => 'lease_type',
			'value'   => $lease_type,
			'compare' => '='
		];
	}

	if (!empty($amenities)) {
		$args['meta_query'][] = [
			'key'     => 'amenities',
			'value'   => $amenities,
			'compare' => '='
		];
	}

	if (!empty($footfall)) {
		$args['meta_query'][] = [
			'key'     => 'footfall',
			'value'   => $footfall,
			'compare' => '='
		];
	}

	if (!empty($visibility)) {
		$args['meta_query'][] = [
			'key'     => 'visibility',
			'value'   => $visibility,
			'compare' => '='
		];
	}

	if (!empty($ceilingHeight)) {
		$args['meta_query'][] = [
			'key'     => 'ceilingHeight',
			'value'   => $ceilingHeight,
			'compare' => '='
		];
	}

	if (!empty($loadingFacilities)) {
		$args['meta_query'][] = [
			'key'     => 'loadingFacilities',
			'value'   => $loadingFacilities,
			'compare' => '='
		];
	}

	if (!empty($house_parking)) {
		$args['meta_query'][] = [
			'key'     => 'house-parking',
			'value'   => $house_parking,
			'compare' => '='
		];
	}

	if (!empty($sharing_type)) {
		$args['meta_query'][] = [
			'key'     => 'sharing-type',
			'value'   => $sharing_type,
			'compare' => '='
		];
	}

	if (!empty($gender)) {
		$args['meta_query'][] = [
			'key'     => 'gender',
			'value'   => $gender,
			'compare' => '='
		];
	}

	if (!empty($food_included)) {
		$args['meta_query'][] = [
			'key'     => 'food-included',
			'value'   => $food_included,
			'compare' => '='
		];
	}

	if (!empty($bathroom)) {
		$args['meta_query'][] = [
			'key'     => 'bathroom',
			'value'   => $bathroom,
			'compare' => '='
		];
	}

	if (!empty($cabins)) {
		$args['meta_query'][] = [
			'key'     => 'cabins',
			'value'   => $cabins,
			'compare' => '='
		];
	}if (!empty($open_space_option)) {
		$args['meta_query'][] = [
			'key'     => 'open_space_option',
			'value'   => $open_space_option,
			'compare' => '='
		];
	}
	//

	if (!empty($prefered_floor)) {
		$args['meta_query'][] = [
			'key'     => 'prefered_floor',
			'value'   => $prefered_floor,
			'compare' => '='
		];
	}
	if (!empty($seating_capacity)) {
		$args['meta_query'][] = [
			'key'     => 'seating_capacity',
			'value'   => $seating_capacity,
			'compare' => '='
		];
	} 
    // Execute query
    $query = new \WP_Query($args);
    $results = [];
	
    $all_products = array();
	if ($query->have_posts()) {
		while ($query->have_posts()) {
			$query->the_post();
			$product_id = get_the_ID();
			// Get WC product object safely
			$product = wc_get_product($product_id);
			if ($product) {
				$all_products[] = array(
					'id'        => $product_id,
					'name'      => $product->get_name(),
					'price'     => $product->get_price(),
					'image'     => get_the_post_thumbnail_url($product_id, 'medium') ?: '',
					'permalink' => get_permalink($product_id)
				);
			}
		}
		wp_reset_postdata();
	}
	
//echo "<pre>"; print_r($all_products); die('yess');
	// Return as a WP REST API response
	
	echo json_encode([
    'success' => true,
    'message' => 'Results fetched successfully.',
    'results'    => $all_products
	]);
	exit;

}









}
