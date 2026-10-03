<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class TokenModel extends Model {
    protected $table = 'refresh_tokens';
    protected $primary_key = 'id';
    protected $fillable = ['user_id', 'token', 'expires_at', 'jti'];
    protected $guarded = ['id'];

    public function save_token($user_id, $token, $expires_at, $jti)
    {
        return $this->_insert([
            'user_id'    => $user_id,
            'token'      => $token,
            'expires_at' => $expires_at,
            'jti'        => $jti,
        ]);
    }

    public function find_valid_token($token)
    {
        return $this->db->table($this->table)
            ->where('token', $token)
            ->where('expires_at', '>=', date('Y-m-d H:i:s'))
            ->get();
    }

    public function delete_token($token)
    {
        return $this->db->table($this->table)
            ->where('token', $token)
            ->delete();
    }
}