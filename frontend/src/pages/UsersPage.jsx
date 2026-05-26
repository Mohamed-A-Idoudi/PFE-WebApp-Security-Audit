import { useState, useEffect } from "react";
import { getUsers, createUser, deleteUser } from "../utils/api";
import { Spinner } from "../components/Spinner";

export function UsersPage({ token }) {
  const [users,setUsers]     = useState([]);
  const [loading,setLoading] = useState(true);
  const [error,setError]     = useState("");
  const [success,setSuccess] = useState("");
  const [showForm,setShowForm]= useState(false);
  const [form,setForm]       = useState({email:"",password:"",role:"analyst"});
  const [saving,setSaving]   = useState(false);
  const [deleting,setDeleting]= useState("");

  useEffect(() => { load(); }, [token]);
  async function load() { setLoading(true); try{setUsers(await getUsers(token));}catch(e){setError(e.message);}finally{setLoading(false);} }
  async function handleCreate(e) {
    e.preventDefault(); setSaving(true); setError(""); setSuccess("");
    try { await createUser(form,token); setSuccess("User created."); setForm({email:"",password:"",role:"analyst"}); setShowForm(false); await load(); }
    catch(err){setError(err.message);}finally{setSaving(false);}
  }
  async function handleDelete(id,email) {
    if(!window.confirm(`Delete ${email}?`))return; setDeleting(id);
    try{await deleteUser(id,token);setUsers(p=>p.filter(u=>u.id!==id));}catch(err){setError(err.message);}finally{setDeleting("");}
  }

  return (
    <div>
      <div className="ss-page-header">
        <div><div className="ss-breadcrumb">Admin · Users</div><div className="ss-h1">User Management</div></div>
        <button className="ss-btn ss-btn-primary ss-btn-sm" onClick={()=>setShowForm(f=>!f)}>{showForm?"Cancel":"+ Add User"}</button>
      </div>
      {error&&<div className="ss-notice ss-notice-err ss-mb-4">{error}</div>}
      {success&&<div className="ss-notice ss-notice-ok ss-mb-4">{success}</div>}
      {showForm&&(
        <div className="ss-card ss-mb-4" style={{maxWidth:"400px"}}>
          <div className="ss-h3" style={{marginBottom:"14px"}}>Create User</div>
          <form onSubmit={handleCreate} style={{display:"flex",flexDirection:"column",gap:"12px"}}>
            <div className="ss-field"><label className="ss-label">Email</label><input className="ss-input" type="email" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} placeholder="user@securiscan.local" required/></div>
            <div className="ss-field"><label className="ss-label">Password</label><input className="ss-input" type="password" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))} placeholder="Min 8 characters" required minLength={8}/></div>
            <div className="ss-field"><label className="ss-label">Role</label><select className="ss-input" value={form.role} onChange={e=>setForm(f=>({...f,role:e.target.value}))}><option value="analyst">Analyst</option><option value="admin">Admin</option></select></div>
            <div className="ss-flex ss-gap-2 ss-mt-2">
              <button type="submit" className="ss-btn ss-btn-primary" disabled={saving}>{saving&&<Spinner size={13} color="#fff"/>}{saving?"Creating…":"Create"}</button>
              <button type="button" className="ss-btn ss-btn-ghost" onClick={()=>setShowForm(false)}>Cancel</button>
            </div>
          </form>
        </div>
      )}
      <div className="ss-card-bare">
        {loading?<div className="ss-empty"><Spinner size={22}/><p>Loading…</p></div>
        :users.length===0?<div className="ss-empty"><p>No users.</p></div>
        :(
          <table className="ss-table">
            <thead><tr><th>Email</th><th>Role</th><th>Created</th><th style={{width:86}}>Actions</th></tr></thead>
            <tbody>
              {users.map(u=>(
                <tr key={u.id} style={{cursor:"default"}}>
                  <td><span style={{fontFamily:"var(--font-mono)",fontSize:"12px"}}>{u.email}</span></td>
                  <td><span style={{padding:"2px 7px",borderRadius:"var(--r-xs)",fontSize:"10px",fontFamily:"var(--font-hd)",letterSpacing:".5px",textTransform:"uppercase",fontWeight:600,background:u.role==="admin"?"rgba(99,102,241,.1)":"var(--raised)",color:u.role==="admin"?"#a5b4fc":"var(--dim)",border:u.role==="admin"?"1px solid rgba(99,102,241,.22)":"1px solid var(--wire)"}}>{u.role}</span></td>
                  <td style={{fontSize:"12px",color:"var(--dim)"}}>{u.created_at?new Date(u.created_at).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}):"—"}</td>
                  <td><button className="ss-btn ss-btn-danger ss-btn-sm" onClick={()=>handleDelete(u.id,u.email)} disabled={deleting===u.id}>{deleting===u.id&&<Spinner size={11} color="var(--crit)"/>}Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
