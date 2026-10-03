<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class ApiController extends Controller
{
    public function __construct()
    {
        parent::__construct();
        handle_cors();
        $this->call->model('AuthModel');
        $this->call->model('TokenModel');
        $this->call->model('ProductModel');
    }

    // ---------- helpers ----------
    private function json($data, $status = 200)
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    private function body()
    {
        return json_decode(file_get_contents('php://input'), true) ?: [];
    }

    private function bearer_token()
    {
        // 1. Try getallheaders()
        $h = getallheaders();
        if (!empty($h['Authorization'])) {
            return str_replace('Bearer ', '', $h['Authorization']);
        }
        if (!empty($h['authorization'])) {
            return str_replace('Bearer ', '', $h['authorization']);
        }

        // 2. $_SERVER fallback (PHP built-in server)
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            return str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
        }
        if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            return str_replace('Bearer ', '', $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
        }

        // 3. apache_request_headers() if available
        if (function_exists('apache_request_headers')) {
            $arh = apache_request_headers();
            $key = 'Authorization';
            if (!empty($arh[$key])) {
                return str_replace('Bearer ', '', $arh[$key]);
            }
            if (!empty($arh['authorization'])) {
                return str_replace('Bearer ', '', $arh['authorization']);
            }
        }

        // 4. Last resort: read from raw header line
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $k => $v) {
                if (strtolower($k) === 'authorization') {
                    return str_replace('Bearer ', '', $v);
                }
            }
        }

        return null;
    }

    private function require_auth()
    {
        $token = $this->bearer_token();
        if (!$token) $this->json(['status' => 'error', 'message' => 'Authentication required.'], 401);

        $record = $this->TokenModel->find_valid_token($token);
        if (!$record) $this->json(['status' => 'error', 'message' => 'Invalid or expired token.'], 401);

        $user = $this->AuthModel->find_by_id($record['user_id']);
        if (!$user) $this->json(['status' => 'error', 'message' => 'User not found.'], 401);

        return $user;
    }

    // ---------- auth ----------
    public function register()
    {
        $data = $this->body();
        if (empty($data['username']) || empty($data['email']) || empty($data['password'])) {
            return $this->json(['status' => 'error', 'message' => 'username, email, and password are required.'], 400);
        }
        if ($this->AuthModel->find_by_identifier($data['username'])) {
            return $this->json(['status' => 'error', 'message' => 'Username already taken.'], 409);
        }
        if ($this->AuthModel->find_by_identifier($data['email'])) {
            return $this->json(['status' => 'error', 'message' => 'Email already registered.'], 409);
        }

        $this->AuthModel->create_user([
            'username'  => $data['username'],
            'email'     => $data['email'],
            'password'  => password_hash($data['password'], PASSWORD_BCRYPT),
            'role'      => $data['role'] ?? 'user',
            'is_active' => 1,
        ]);

        return $this->json(['status' => 'success', 'message' => 'Account created successfully.']);
    }

    public function login()
    {
        $data = $this->body();
        if (empty($data['identifier']) || empty($data['password'])) {
            return $this->json(['status' => 'error', 'message' => 'identifier and password are required.'], 400);
        }

        $user = $this->AuthModel->find_by_identifier($data['identifier']);
        if (!$user || !password_verify($data['password'], $user['password'])) {
            return $this->json(['status' => 'error', 'message' => 'Invalid credentials.'], 401);
        }

        $token = bin2hex(random_bytes(32));
        $jti   = bin2hex(random_bytes(16));
        $this->TokenModel->save_token($user['id'], $token, date('Y-m-d H:i:s', strtotime('+7 days')), $jti);

        return $this->json([
            'status'  => 'success',
            'message' => 'Login successful.',
            'token'   => $token,
            'user'    => [
                'id'       => $user['id'],
                'username' => $user['username'],
                'email'    => $user['email'],
                'role'     => $user['role'],
            ],
        ]);
    }

    public function logout()
    {
        $token = $this->bearer_token();
        if ($token) $this->TokenModel->delete_token($token);
        return $this->json(['status' => 'success', 'message' => 'Logged out.']);
    }

    public function profile()
    {
        $user = $this->require_auth();
        unset($user['password']);
        return $this->json(['status' => 'success', 'user' => $user]);
    }

    public function refresh()
    {
        $user  = $this->require_auth();
        $token = bin2hex(random_bytes(32));
        $jti   = bin2hex(random_bytes(16));
        $this->TokenModel->save_token($user['id'], $token, date('Y-m-d H:i:s', strtotime('+7 days')), $jti);
        return $this->json(['status' => 'success', 'token' => $token]);
    }

    // ---------- product CRUD ----------
    public function list()
    {
        $this->require_auth();
        $products = $this->ProductModel->_order_by('id', 'DESC');
        return $this->json(['status' => 'success', 'data' => $products]);
    }

    public function create()
    {
        $this->require_auth();
        $data = $this->body();
        if (empty($data['product_name']) || !isset($data['price'])) {
            return $this->json(['status' => 'error', 'message' => 'product_name and price are required.'], 400);
        }

        $id = $this->ProductModel->_insert([
            'product_name' => $data['product_name'],
            'description'  => $data['description'] ?? '',
            'price'        => $data['price'],
            'quantity'     => $data['quantity'] ?? 0,
        ]);
        return $id
            ? $this->json(['status' => 'success', 'message' => 'Product created.', 'id' => $id], 201)
            : $this->json(['status' => 'error', 'message' => 'Failed to create product.'], 500);
    }

    public function update($id = null)
    {
        $this->require_auth();
        $data = $this->body();
        if (!$id) return $this->json(['status' => 'error', 'message' => 'Product ID required.'], 400);

        $existing = $this->ProductModel->_find($id);
        if (!$existing) return $this->json(['status' => 'error', 'message' => 'Product not found.'], 404);

        $update = [];
        if (isset($data['product_name'])) $update['product_name'] = $data['product_name'];
        if (isset($data['description']))  $update['description']  = $data['description'];
        if (isset($data['price']))        $update['price']        = $data['price'];
        if (isset($data['quantity']))     $update['quantity']     = $data['quantity'];
        if (empty($update)) return $this->json(['status' => 'error', 'message' => 'No fields to update.'], 400);

        $this->ProductModel->_update($id, $update);
        return $this->json(['status' => 'success', 'message' => 'Product updated.']);
    }

    public function delete($id = null)
    {
        $this->require_auth();
        if (!$id) return $this->json(['status' => 'error', 'message' => 'Product ID required.'], 400);

        $existing = $this->ProductModel->_find($id);
        if (!$existing) return $this->json(['status' => 'error', 'message' => 'Product not found.'], 404);

        $this->ProductModel->_delete($id);
        return $this->json(['status' => 'success', 'message' => 'Product deleted.']);
    }
}