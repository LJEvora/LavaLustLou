<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class AuthModel extends Model {
    protected $table = 'users';
    protected $primary_key = 'id';
    protected $fillable = ['username', 'email', 'password', 'role', 'is_active'];
    protected $guarded = ['id'];

    public function find_by_identifier($identifier)
    {
        return $this->db->table($this->table)
            ->where('username', $identifier)
            ->or_where('email', $identifier)
            ->get();
    }

    public function find_by_id($id)
    {
        return $this->_find($id);
    }

    public function create_user($data)
    {
        return $this->_insert($data);
    }
}