import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../lib/api';
import '../styles/AdminPanel.css';

interface User {
  id: string;
  username: string;
  email: string;
  role: 'user' | 'admin';
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export const AdminPanel: React.FC = () => {
  const { isAdmin } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<User>>({});

  if (!isAdmin) {
    return <div className="admin-panel-error">访问被拒绝。仅限管理员。</div>;
  }

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await api.get('/admin/users?limit=100');
      setUsers(response.data.items);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载用户失败');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (user: User) => {
    setEditingId(user.id);
    setEditForm(user);
  };

  const handleSaveEdit = async () => {
    if (!editingId) return;

    try {
      await api.patch(`/admin/users/${editingId}`, editForm);
      setEditingId(null);
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : '更新用户失败');
    }
  };

  const handleDelete = async (userId: string) => {
    if (!window.confirm('确定要删除此用户吗?')) return;

    try {
      await api.delete(`/admin/users/${userId}`);
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : '删除用户失败');
    }
  };

  const handleToggleActive = async (user: User) => {
    try {
      await api.patch(`/admin/users/${user.id}`, {
        is_active: !user.is_active
      });
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : '更新用户状态失败');
    }
  };

  return (
    <div className="admin-panel">
      <h1>用户管理</h1>

      {error && <div className="admin-error">{error}</div>}

      {loading ? (
        <div className="admin-loading">加载中...</div>
      ) : (
        <div className="users-table-container">
          <table className="users-table">
            <thead>
              <tr>
                <th>用户名</th>
                <th>邮箱</th>
                <th>角色</th>
                <th>状态</th>
                <th>最后登录</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className={editingId === user.id ? 'editing' : ''}>
                  <td>
                    {editingId === user.id ? (
                      <input
                        type="text"
                        value={editForm.username || ''}
                        onChange={(e) =>
                          setEditForm({ ...editForm, username: e.target.value })
                        }
                      />
                    ) : (
                      user.username
                    )}
                  </td>
                  <td>
                    {editingId === user.id ? (
                      <input
                        type="email"
                        value={editForm.email || ''}
                        onChange={(e) =>
                          setEditForm({ ...editForm, email: e.target.value })
                        }
                      />
                    ) : (
                      user.email
                    )}
                  </td>
                  <td>
                    {editingId === user.id ? (
                      <select
                        value={editForm.role || 'user'}
                        onChange={(e) =>
                          setEditForm({
                            ...editForm,
                            role: e.target.value as 'user' | 'admin',
                          })
                        }
                      >
                        <option value="user">普通用户</option>
                        <option value="admin">管理员</option>
                      </select>
                    ) : (
                      <span className={`role-badge role-${user.role}`}>
                        {user.role === 'admin' ? '管理员' : '普通用户'}
                      </span>
                    )}
                  </td>
                  <td>
                    <button
                      className={`status-badge ${
                        user.is_active ? 'active' : 'inactive'
                      }`}
                      onClick={() => handleToggleActive(user)}
                    >
                      {user.is_active ? '活跃' : '禁用'}
                    </button>
                  </td>
                  <td>
                    {user.last_login_at
                      ? new Date(user.last_login_at).toLocaleDateString('zh-CN')
                      : '从未'}
                  </td>
                  <td className="actions-cell">
                    {editingId === user.id ? (
                      <>
                        <button
                          className="btn-save"
                          onClick={handleSaveEdit}
                        >
                          保存
                        </button>
                        <button
                          className="btn-cancel"
                          onClick={() => setEditingId(null)}
                        >
                          取消
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          className="btn-edit"
                          onClick={() => handleEdit(user)}
                        >
                          编辑
                        </button>
                        <button
                          className="btn-delete"
                          onClick={() => handleDelete(user.id)}
                        >
                          删除
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="admin-stats">
        <div className="stat">
          <label>用户总数</label>
          <span>{users.length}</span>
        </div>
        <div className="stat">
          <label>管理员</label>
          <span>{users.filter((u) => u.role === 'admin').length}</span>
        </div>
        <div className="stat">
          <label>活跃用户</label>
          <span>{users.filter((u) => u.is_active).length}</span>
        </div>
      </div>
    </div>
  );
};
