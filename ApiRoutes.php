<?php
namespace RestMyApis\Routes;

use WP_REST_Controller;
use WP_REST_Request;
use WP_REST_Response;
use RestMyApis\Services\HelperService;



class ApiRoutes extends WP_REST_Controller  {

    public function __construct() {
        $this->namespace = 'my-api/v1';
        $this->rest_base = 'auth';
        $this->register_routes();
    }

    public function register_routes() {
        register_rest_route( $this->namespace, '/login', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_login' ],
            'permission_callback' => '__return_true',
        ] );
		//This api for logout the user from APP with expo token 
		
		register_rest_route( $this->namespace, '/logout', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_logout' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/to_let_service_registration', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_to_let_service_registration' ],
            'permission_callback' => '__return_true',
        ] );
		
		register_rest_route( $this->namespace, '/login_with_otp', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_login_with_otp' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/resend_otp', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_resend_otp' ],
            'permission_callback' => '__return_true',
        ] );
		
		// register_rest_route( $this->namespace, '/verify_otp_', [
            // 'methods' => 'POST',
            // 'callback' => [ $this, 'handle_verify_otp' ],
            // 'permission_callback' => '__return_true',
        // ] );

        register_rest_route( $this->namespace, '/signup', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_signup' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/service_provider_detail', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_service_provider_detail' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/service_provider_approval', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_status' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/register', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_sewamitra' ],
            'permission_callback' => '__return_true',
        ] );
        register_rest_route( $this->namespace, '/service_provider_order_details', [
            'methods' => 'POST',
            'callback' => [ $this, 'dashboard_service_provider' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/service_provider_edit_information', [
            'methods' => 'POST',
            'callback' => [ $this, 'edit_information_service_provider' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/reset_password', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_reset_password' ],
            'permission_callback' => '__return_true',
        ] );
		
	
		register_rest_route($this->namespace, '/get_form_csrf/', [
			'methods' => 'GET',
			'callback' => [ $this,'get_dynamic_form_and_csrf_rest']
		]);
			register_rest_route('my-api/v1', '/property_results', [
			'methods'  => 'POST',
			'callback' => [$this, 'handle_search_property_results'],
			'permission_callback' => '__return_true',
		]);

		register_rest_route( $this->namespace, '/get_categories', [
            'methods' => 'GET',
            'callback' => [ $this, 'handle_get_catogories' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/get_sub_categories', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_get_sub_categories' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/products', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_get_product_details' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/product_details', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_get_product_detail_page' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/most_book_services', [
            'methods' => 'GET',
            'callback' => [ $this, 'most_booked_services' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/user_profile', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_get_user_profile' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/change_user_password', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_change_user_password' ],
            'permission_callback' => '__return_true',
        ] );
        register_rest_route( $this->namespace, '/user_bookings', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_user_bookings' ],
            'permission_callback' => '__return_true',
        ]);
		register_rest_route( $this->namespace, '/order_bookings', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_order_bookings' ],
            'permission_callback' => '__return_true',
        ]);
        register_rest_route($this->namespace, '/update_user_profile',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_user_profile_update'],
                'permission_callback' => '__return_true',
        ] );
		//This API for update the service provider like Pending ,Deny and Approved 
		 register_rest_route($this->namespace, '/update_service_provider_status',
            [
                'methods' => 'POST',
                'callback' => [$this, 'update_service_provider'],
                'permission_callback' => '__return_true',
        ] );
			register_rest_route($this->namespace, '/delete_account',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_delete_account'],
                'permission_callback' => '__return_true',
        ] );
        	register_rest_route($this->namespace, '/add_to_favourites',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_add_to_wishlist'],
                'permission_callback' => '__return_true',
        ] );
        register_rest_route($this->namespace, '/remove_from_favourites',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_remove_from_wishlist'],
                'permission_callback' => '__return_true',
        ] );
		register_rest_route($this->namespace, '/booking_api',
            [
                'methods' => 'POST',
                'callback' => [$this, 'booking_api'],
                'permission_callback' => '__return_true',
        ] );
			
		register_rest_route($this->namespace, '/user_orders_details',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_user_orders_details'],
                'permission_callback' => '__return_true',
        ] );
		register_rest_route($this->namespace, '/booking_status_update',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_booking_status_update'],
                'permission_callback' => '__return_true',
        ] );
        register_rest_route($this->namespace, '/get_reviews',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_get_reviews'],
                'permission_callback' => '__return_true',
        ] );
        register_rest_route($this->namespace, '/write_review',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_write_a_review'],
                'permission_callback' => '__return_true',
        ] );
		
		register_rest_route($this->namespace, '/create_booking', [
			'methods' => 'POST',
			'callback' => [$this,'handle_booking_request'],
			'permission_callback' => '__return_true',
		]);
		
		register_rest_route($this->namespace, '/appointments', [
			'methods' => 'POST',
			'callback' => [$this,'create_bookly_appointment']
		]); 
		register_rest_route($this->namespace, '/get_bookly_available_slots', [
			'methods' => 'POST',
			'callback' => [$this,'available_time_slots']
		]);
		register_rest_route( $this->namespace, '/sub_categories', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_sub_categories' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/child_sub_categories', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_child_sub_categories' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/search_box', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_search_box' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/recent_orders', [
            'methods' => 'GET',
            'callback' => [ $this, 'handle_recent_orders' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/save_token', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_save_fcm_token' ],
            'permission_callback' => '__return_true',
        ] );
		register_rest_route( $this->namespace, '/single_property', [
            'methods' => 'POST',
            'callback' => [ $this, 'handle_single_property' ],
            'permission_callback' => '__return_true',
        ] );
		// dfdf
		
    }
	function verify_msg91_otp2() {
		//echo "sdfsdf";die;
	}
	function get_dynamic_form_and_csrf_rest() {
		$data = HelperService::generate_dynamic_form_and_csrf();
		return new WP_REST_Response($data, 200);
	}
	
	
 public function handle_single_property($request) {
    if (function_exists('ob_get_level')) {
        while (ob_get_level()) {
            ob_end_clean(); // Clear all output buffers
        }
    }

    header_remove(); // Remove any set headers

    return new \WP_REST_Response([
        'success' => true,
        'message' => 'Clean response'
    ], 200);
}


		
	
	
	 public function handle_recent_orders($request) {
		
		$validate = self::validate_jwt_token($request);
        if(!$validate['success']){
            return new \WP_REST_Response([
            'success' => false,
            'message' => $validate['message']
        ], 401);}
       
		$user_id = $validate['user_id'];
			
		
		$response = HelperService::recent_orders($user_id);
		
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
			} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		} 
		
	}
public function edit_information_service_provider($request) {
    $validate = self::validate_jwt_token($request);
    if (!$validate['success']) {
        return new \WP_REST_Response([
            'success' => false,
            'message' => $validate['message']
        ], 401);
    }

    // Use get_params() to support form-data, JSON, and url-encoded data
    $data = $request->get_params();

    // Call the function and get the response
    $response = HelperService::edit_information_sewa_mitra($data);

    // Check if the response is a WP_REST_Response
    $response_data = $response instanceof \WP_REST_Response
        ? $response->get_data()
        : $response;

    // Return proper error or success response
    if (!empty($response_data['success'])) {
        return new \WP_REST_Response($response_data, 200);
    } else {
        return new \WP_REST_Response([
            'success' => false,
            'message' => $response_data['message'] ?? 'Unknown error occurred.',
            'errors'  => $response_data['errors'] ?? null,
        ], 400);
    }
}


	public function update_service_provider($request) {
		$params = $request->get_json_params();
		
	    $user_id = $params['user_id'] ?? null;
		$status = $params['status'] ?? null;		
		
		$response = HelperService::update_service_provider_status($request);

		// If response is already a WP_REST_Response, return it as-is
		if ($response instanceof WP_REST_Response) {
			return $response;
		}

		// Handle a valid array-based response
		if (is_array($response)) {
			if (!empty($response['status']) && $response['status'] === 'success') {
				return new WP_REST_Response($response, 200);
			} else {
				return new WP_REST_Response([
					'status' => 'error',
					'message' => $response['message'] ?? 'Something went wrong.'
				], 401);
			}
		}

		// Default fallback
		return new WP_REST_Response([
			'status' => 'error',
			'message' => 'Invalid response from HelperService.'
		], 500);
	}

  public function handle_to_let_service_registration($request) {
	  
        $response = HelperService::handle_to_let_service_registration($request);

        if ($response instanceof WP_REST_Response) {
            $response_data = $response->get_data();

            if (!empty($response_data['success'])) {
                return new WP_REST_Response($response_data, 200);
            } else {
                return new WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message'] ?? 'Something went wrong.'
                ], 401);
            }
        } else {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }


 public function handle_service_provider_detail($request) {
	 
        $response = HelperService::handle_service_provider_details($request);

        if ($response instanceof \WP_REST_Response) {
            $response_data = $response->get_data();

            if (!empty($response_data['success']) && $response_data['success']) {
                return new \WP_REST_Response($response_data, 200);
            } else {
                return new \WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message'] ?? 'Something went wrong.'
                ], 401);
            }
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }

   public function handle_user_orders_details($request) {
        $response = HelperService::handle_orders_details_user($request);

        if ($response instanceof \WP_REST_Response) {
            $response_data = $response->get_data();

            if (!empty($response_data['success']) && $response_data['success']) {
                return new \WP_REST_Response($response_data, 200);
            } else {
                return new \WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message'] ?? 'Something went wrong.'
                ], 401);
            }
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }



  public function handle_status($request) {
	  //echo"asdfds";die;
	  header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Headers: *");
	  $response = HelperService::handle_approval_status();

        if ($response instanceof \WP_REST_Response) {
            $response_data = $response->get_data();

            if ($response_data['success']) {
                return new \WP_REST_Response($response_data, 200);
            } else {
                return new \WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message']
                ], 401);
            }
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }
  // Handling logout of APP
	  public function handle_logout($request) {
		 // echo "df;lkdsjkfk;l";die;
        $response = HelperService::handle_logout_with_expo($request);

        if ($response instanceof \WP_REST_Response) {
            $response_data = $response->get_data();

            if ($response_data['success']) {
                return new \WP_REST_Response($response_data, 200);
            } else {
                return new \WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message']
                ], 401);
            }
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }
	
	
	
	
    public function dashboard_service_provider($request) {
        $response = HelperService::sewa_mitra_dashboard($request);

        if ($response instanceof \WP_REST_Response) {
            $response_data = $response->get_data();

            if ($response_data['success']) {
                return new \WP_REST_Response($response_data, 200);
            } else {
                return new \WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message']
                ], 401);
            }
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }


    
    public function handle_booking_status_update($request) {
		//echo"adfs";die;
		$response = HelperService::bookingstatusUpdate($request);
		// echo "<pre>";print_r($response);die;
		if ($response instanceof \WP_REST_Response) {
			// Get the data from the WP_REST_Response
			$response_data = $response->get_data();

			// Check if 'success' is true
			if ($response_data['success']) {
				// Return a new WP_REST_Response with the data and a 200 status code
				return new \WP_REST_Response($response_data, 200);
			} else {
				// Return a new WP_REST_Response with an error message and a 401 status code
				return new \WP_REST_Response([
					'success' => false,
					'message' => $response_data['message']
				], 401);
			}
		} else {
			// If $response is not a WP_REST_Response, return an error response
			return new \WP_REST_Response([
				'success' => false,
				'message' => 'Invalid response from HelperService.'
			], 500);
		}	
	}
	public function handle_search_box($request) {
		//echo"adfs";die;
		$response = HelperService::search_box($request);
		
		if ($response instanceof \WP_REST_Response) {
			// Get the data from the WP_REST_Response
			$response_data = $response->get_data();

			// Check if 'success' is true
			if ($response_data['success']) {
				// Return a new WP_REST_Response with the data and a 200 status code
				return new \WP_REST_Response($response_data, 200);
			} else {
				// Return a new WP_REST_Response with an error message and a 401 status code
				return new \WP_REST_Response([
					'success' => false,
					'message' => $response_data['message']
				], 401);
			}
		} else {
			// If $response is not a WP_REST_Response, return an error response
			return new \WP_REST_Response([
				'success' => false,
				'message' => 'Invalid response from HelperService.'
			], 500);
		}	
	}
    public function handle_child_sub_categories($request) {
		//echo"jfldsjk";die;
		$response = HelperService::child_sub_categories($request);

		// Check if the response is an instance of WP_REST_Response
		if ($response instanceof \WP_REST_Response) {
			// Get the data from the WP_REST_Response
			$response_data = $response->get_data();

			// Check if 'success' is true
			if ($response_data['success']) {
				// Return a new WP_REST_Response with the data and a 200 status code
				return new \WP_REST_Response($response_data, 200);
			} else {
				// Return a new WP_REST_Response with an error message and a 401 status code
				return new \WP_REST_Response([
					'success' => false,
					'message' => $response_data['message']
				], 401);
			}
		} else {
			// If $response is not a WP_REST_Response, return an error response
			return new \WP_REST_Response([
				'success' => false,
				'message' => 'Invalid response from HelperService.'
			], 500);
		}
		
	}
    public function handle_sub_categories($request) {
		// Call the HelperService sub_categories method
		$response = HelperService::sub_categories($request);

		// Check if the response is an instance of WP_REST_Response
		if ($response instanceof \WP_REST_Response) {
			// Get the data from the WP_REST_Response
			$response_data = $response->get_data();

			// Check if 'success' is true
			if ($response_data['success']) {
				// Return a new WP_REST_Response with the data and a 200 status code
				return new \WP_REST_Response($response_data, 200);
			} else {
				// Return a new WP_REST_Response with an error message and a 401 status code
				return new \WP_REST_Response([
					'success' => false,
					'message' => $response_data['message']
				], 401);
			}
		} else {
			// If $response is not a WP_REST_Response, return an error response
			return new \WP_REST_Response([
				'success' => false,
				'message' => 'Invalid response from HelperService.'
			], 500);
		}
	}

    public function handle_login( WP_REST_Request $request ) {
        $identifier = $request->get_param( 'identifier');
        $password = $request->get_param( 'password' );
		$fcm_tokens = $request->get_param( 'token' );
		
        $response = HelperService::validate_user_credentials($identifier, $password, $fcm_tokens);

        if ($response['success']) {
            return new \WP_REST_Response($response, 200);
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => $response['message']
            ], 401);
        }
    }
	
	public function handle_resend_otp( WP_REST_Request $request ) {
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Headers: *");
		$identifier = $request->get_param( 'identifier');
        $response = resend_otp_app($identifier);

        if ($response['success']) {
            return new \WP_REST_Response($response, 200);
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => $response['message']
            ], 401);
        }
	}
	public function handle_login_with_otp( WP_REST_Request $request ) {
		$identifier = $request->get_param( 'identifier');
		$token = $request->get_param( 'token');
        $response = HelperService::validate_user_credentials_with_identifier($identifier, $token);

        if ($response['success']) {
            return new \WP_REST_Response($response, 200);
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => $response['message']
            ], 401);
        }
    }
	
	public function handle_verify_otp( WP_REST_Request $request ) {
		$otp = $request->get_param( 'otp');
		$identifier = $request->get_param( 'identifier');
		
		$response = wp_remote_post(home_url('/verify_otp_set'), [
			'body' => json_encode([
				 'identifier'     => $identifier,
                'otp'        => $otp
			]),
			'headers' => [
				'Content-Type' => 'application/json',
			],
		]);

		//print_r($response);die;
        // $response = verfiy_user_otp($otp);

        if ($response['success']) {
            return new \WP_REST_Response($response, 200);
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => $response['message']
            ], 401);
        }
    }
    public function validate_jwt_token($request) {
		
		// Check if the class exists
		if (!class_exists('Jwt_Auth_Public')) {
			return [
				'success' => false,
				'message' => 'JWT Authentication plugin is missing or inactive.'
			];
		}

		// Create an instance of Jwt_Auth_Public
		// $jwt_auth = new Jwt_Auth_Public('jwt_auth', '1');

		// Get the Authorization header
		$auth_header = !empty($_SERVER['HTTP_AUTHORIZATION']) ? sanitize_text_field($_SERVER['HTTP_AUTHORIZATION']) : false;
		
		if (!$auth_header) {
			$auth_header = !empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? sanitize_text_field($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) : false;
		}
		
		$jwt_token = str_replace('Bearer ', '', $auth_header);
		
		$response = HelperService::decode_jwt_token($jwt_token);
		if($response)
		{
			
			return [
					'success' => true,
					'message' => 'Valid token.',
					'user_id' => $response['data']['user']['id']
				];
		}
		else
		{
			return [
					'success' => false,
					'message' => 'Invalid token.'
				];
		}


	}
    public function handle_signup( WP_REST_Request $request ) {
        
        $data = $request->get_params();
        //echo '<pre>';print_r($data);die;
        $response = HelperService::signup_user($data);
         if ($response['success']) {
            return new \WP_REST_Response($response, 200);
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => $response['message']
            ], 401);
        }
       
    }
	public function handle_sewamitra( WP_REST_Request $request ) {
    // This handles both form-data fields and files correctly
    $params = $request->get_body_params(); // For form-data fields
    $files = $request->get_file_params();  // For uploaded files

    $response = HelperService::register_sewamitra($params, $files);

    return ($response instanceof \WP_REST_Response)
        ? $response
        : new \WP_REST_Response([
            'success' => false,
            'message' => 'Unexpected error.'
        ], 500);
}

	
	
    
	public function handle_reset_password($request){
		$identify = $request->get_param('identify');
		$response = HelperService::forget_password($identify);

		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		}
	}
			
    public function handle_get_catogories(){
        
        $response = HelperService::get_catogories();
        
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		} 
	}
	public function handle_get_sub_categories($request){
		$response = HelperService::get_subcategories($request);
		
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		} 
		
	}
	public function handle_get_product_details($request){
		
		$subcategory_id = $request['id']; // Get product ID from request
		$response = HelperService::get_product_details($subcategory_id);

		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		} 
	}
	
	public function handle_get_product_detail_page($request){
		
		$product_id = $request['id']; // Get product ID from request
		if(empty($product_id))
		{
			return new \WP_REST_Response([
				'success' => false,
				'message' => "Please select any Product or Category"
			]);	
		}	
			
		$response = HelperService::get_product_detail_page($product_id);

		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => "No Product Found"
			]);
		} 
	}

    public function most_booked_services() {
		$response = HelperService::most_booked_services();

		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		} 
	}
			
	public function handle_get_user_profile($request){
		$validate = self::validate_jwt_token($request);
        if(!$validate['success']){
            return new \WP_REST_Response([
            'success' => false,
            'message' => $validate['message']
        ], 401);}
         // echo "<pre>";print_r($validate);die;
		$user_id = $validate['user_id'];
			// $user_id = $request['user_id'];
		
		$response = HelperService::get_user_profile($user_id);
		
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
			} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		} 
	}
	public function handle_change_user_password($request){
	    $validate = self::validate_jwt_token($request);
        if(!$validate['success']){
            return new \WP_REST_Response([
            'success' => false,
            'message' => $validate['message']
        ], 401);}
			$response = HelperService::change_user_password($request);
			 if ($response['success']) {
				return new \WP_REST_Response($response, 200);
				} else {
			    return new \WP_REST_Response([
					'success' => false,
					'message' => $response['message']
				]);
				}
			
	}
	
	public function handle_order_bookings($request){
	    $validate = self::validate_jwt_token($request);
        if(!$validate['success']){
            return new \WP_REST_Response([
            'success' => false,
            'message' => $validate['message']
        ], 401);}
		$response = HelperService::update_order_booking($request);
		 if ($response['success']) {
			return new \WP_REST_Response($response, 200);
			} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
			}
			
	}
	
	public function handle_user_bookings($user_id){
		$user_id = $user_id['user_id'];
		
		$response = HelperService::get_user_bookings_data($user_id);
		if ($response['success']) {
					return new \WP_REST_Response($response, 200);
					} else {
					return new \WP_REST_Response([
						'success' => false,
						'message' => $response['message']
					]);
					}

	}

    public function handle_user_profile_update($data){
        
      
        $validate = self::validate_jwt_token($data);
        if(!$validate['success']){
            return new \WP_REST_Response([
            'success' => false,
            'message' => $validate['message']
        ], 401);}
         // echo "<pre>";print_r($validate);die;
		$user_id = $validate['user_id'];
        $response = HelperService::user_profile_update($data,$user_id);
        if ($response['success']) {
				return new \WP_REST_Response($response, 200);
				} else {
			    return new \WP_REST_Response([
					'success' => false,
					'message' => $response['message']
				]);
				}
        
    }
    public function handle_delete_account($request) {

        $validate = self::validate_jwt_token($request);
            if(!$validate['success']){
                return new \WP_REST_Response([
                'success' => false,
                'message' => $validate['message']
            ], 401);}
        $user_id = $validate['user_id'];
        $password = $request['password'];
        
        $response = HelperService::delete_user_account($user_id, $password);
        
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		}
    }
    public function handle_add_to_wishlist($request) {

        $validate = self::validate_jwt_token($request);
            if(!$validate['success']){
                return new \WP_REST_Response([
                'success' => false,
                'message' => $validate['message']
            ], 401);}
        $user_id = $validate['user_id'];
        $product_id = $request['product_id'];
        
        $response = HelperService::add_to_wishlist($user_id, $product_id);
        
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		}
    }

    public function handle_remove_from_wishlist($request) {

        $validate = self::validate_jwt_token($request);
            if(!$validate['success']){
                return new \WP_REST_Response([
                'success' => false,
                'message' => $validate['message']
            ], 401);}
      
		$user_id = $validate['user_id'];
        $product_id = $request['product_id'];
        
        $response = HelperService::remove_from_wishlist($user_id, $product_id);
        
		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			]);
		}
    }

	public function booking_api($request) {
		global $wpdb;
		// Retrieve request parameters
		$params = $request->get_json_params();

		// Extract the product ID from the array
		$product_id = isset($params['product_id']) ? intval($params['product_id']) : null;

		// Validate required fields
		if (!$product_id) {
			return new \WP_Error('missing_product_id', 'Product ID is missing.', array('status' => 400));
		}

		// Get the WooCommerce product
		$product = wc_get_product($product_id);
		if (!$product) {
			return new \WP_Error('invalid_product', 'Invalid Product ID.', array('status' => 404));
		}

		// Query the Bookly service table to get the Bookly service ID associated with this product
		$service_id = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}bookly_services WHERE wc_product_id = %d",
				$product_id
			)
		);

		if (!$service_id) {
			return new \WP_Error('no_service_id', 'No Bookly service ID associated with this product.', array('status' => 404));
		}

		// Query the Bookly appointments table to fetch calendar data for this service
		$appointments = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, start_date, end_date, status 
				 FROM {$wpdb->prefix}bookly_appointments 
				 WHERE service_id = %d 
				 ORDER BY start_date ASC",
				$service_id
			)
		);

		if (empty($appointments)) {
			return new \WP_Error('no_appointments', 'No appointments found for this service.', array('status' => 404));
		}

		// Format the calendar data
		$calendar = array_map(function($appointment) {
			return array(
				'appointment_id' => $appointment->id,
				'start_date' => $appointment->start_date,
				'end_date' => $appointment->end_date,
				'status' => $appointment->status,
			);
		}, $appointments);

		// Return a success response with calendar data
		return rest_ensure_response(array(
			'success' => true,
			'service_id' => $service_id,
			'calendar' => $calendar,
		));
	}


	// Function to get the Bookly service ID associated with a WooCommerce product ID
	private function get_bookly_service_id_from_product($product_id) {
		// Retrieve the Bookly service ID from the product's metadata (assuming 'bookly_service_id' is set)
		$service_id = get_post_meta($product_id, 'bookly_service_id', true);

		if (!$service_id) {
			return new \WP_Error('no_service_id', 'No Bookly service ID is associated with this product.', array('status' => 404));
		}

		return intval($service_id);  // Return the service ID as an integer
	}



	// Function to create a booking in Bookly
	private function create_bookly_booking($service_id, $customer_name, $customer_email, $appointment_time) {
		global $wpdb;

		// Insert into Bookly's database tables (or use Bookly's API if available)
		$wpdb->insert($wpdb->prefix . 'bookly_customers', array(
			'full_name' => $customer_name,
			'email' => $customer_email,
		));
		$customer_id = $wpdb->insert_id;

		$wpdb->insert($wpdb->prefix . 'bookly_appointments', array(
			'customer_id' => $customer_id,
			'service_id' => $service_id,
			'start_date' => $appointment_time,
		));
		return $wpdb->insert_id;
	}

	// Function to create a WooCommerce order
	private function create_woocommerce_order($product_id, $customer_name, $customer_email) {
		$order = wc_create_order();
		$product = wc_get_product($product_id);

		if (!$product) {
			return new WP_Error('invalid_product', 'Product not found.', array('status' => 404));
		}

		$order->add_product($product, 1); // Add 1 quantity of the product
		$order->set_billing_first_name($customer_name);
		$order->set_billing_email($customer_email);
		$order->calculate_totals();
		$order->save();

		return $order->get_id();
	}
		
    public function handle_get_reviews($request){
    
        $product_id = $request['product_id'];
        $response = HelperService::get_reviews($product_id);
        
        if ($response['success']) {
    		return new \WP_REST_Response($response, 200);
    		} else {
    			 return new \WP_REST_Response([
    			'success' => false,
    			'message' => $response['message']
    		]);
    	}
        
    }
    public function create_bookly_appointment($request) {
		
        $response = HelperService::bookly_appointment($request);
      
        if ($response['success']) {
    		return new \WP_REST_Response($result, 200);
    		} else {
    			 return new \WP_REST_Response([
    			'success' => false,
    			'message' => $result['message']
    		]);
    	}
	}
    public function handle_booking_request($request){
		$validate = self::validate_jwt_token($request);
            if(!$validate['success']){
                return new \WP_REST_Response([
                'success' => false,
                'message' => $validate['message']
            ], 401);}
		$user_id  = $validate['user_id'];
		$request->set_param('customer_id', $user_id);
        $response = HelperService::create_woo_commerce_order($request);
        
        if ($response['success']) {
    		return new \WP_REST_Response($response, 200);
    		} else {
    			 return new \WP_REST_Response([
    			'success' => false,
    			'message' => $response['message']
    		]);
    	}
	}
	public function available_time_slots($request) {
		$validate = self::validate_jwt_token($request);
		if(!$validate['success']){
			return new \WP_REST_Response([
			'success' => false,
			'message' => $validate['message']
		], 401);}
		
		$response = HelperService::bookly_available_slots($request);

	 
		if (is_wp_error($response)) {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response->get_error_message(),
			], 400);
		}

		
		if ($response instanceof \WP_REST_Response) {
			return $response; // Directly return it
		}

		if (!is_array($response) || !isset($response['success'])) {
			return new \WP_REST_Response([
				'success' => false,
				'message' => 'Invalid response format from bookly_available_slots.',
			], 500);
		}

		if ($response['success']) {
			return new \WP_REST_Response($response, 200);
		} else {
			return new \WP_REST_Response([
				'success' => false,
				'message' => $response['message']
			], 400);
		}
	}
public function handle_save_fcm_token($request){
	//echo "sdafsdaf"; die;
	 $response = HelperService::save_fcm_token($request);

        if ($response instanceof \WP_REST_Response) {
            $response_data = $response->get_data();

            if (!empty($response_data['success']) && $response_data['success']) {
                return new \WP_REST_Response($response_data, 200);
            } else {
                return new \WP_REST_Response([
                    'success' => false,
                    'message' => $response_data['message'] ?? 'Something went wrong.'
                ], 401);
            }
        } else {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Invalid response from HelperService.'
            ], 500);
        }
    }


 public function handle_search_property_results($request) {
	 
        $response = HelperService::handle_property_results($request);
      
        if ($response['success']) {
    		return new \WP_REST_Response($result, 200);
    		} else {
    			 return new \WP_REST_Response([
    			'success' => false,
    			'message' => $result['message']
    		]);
    	}
 }


    public function handle_write_a_review($request){
		
        $validate = self::validate_jwt_token($request);
            if(!$validate['success']){
                return new \WP_REST_Response([
                'success' => false,
                'message' => $validate['message']
            ], 401);}
    
        $response = HelperService::write_a_review($request);
        
        if ($response['success']) {
    		return new \WP_REST_Response($response, 200);
    		} else {
    			 return new \WP_REST_Response([
    			'success' => false,
    			'message' => $response['message']
    		]);
    	}
        
    }
			
}
