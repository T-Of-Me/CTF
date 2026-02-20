export default function Dashboard() {
  return (
    <div style={{ maxWidth: '1000px', margin: '50px auto', padding: '20px' }}>
      <div style={{ 
        border: '2px solid #00ff00', 
        borderRadius: '10px', 
        padding: '30px',
        backgroundColor: '#0a0a0a',
        boxShadow: '0 0 20px rgba(0, 255, 0, 0.3)'
      }}>
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          marginBottom: '30px',
          borderBottom: '1px solid #333',
          paddingBottom: '20px'
        }}>
          <div>
            <h1 style={{ color: '#00ff00', margin: 0, fontSize: '32px' }}>
              🎯 Employee Dashboard
            </h1>
            <p style={{ color: '#666', margin: '5px 0 0 0' }}>
              Welcome back, User
            </p>
          </div>
          <div style={{ 
            backgroundColor: '#003300',
            padding: '10px 20px',
            borderRadius: '5px',
            border: '1px solid #00ff00'
          }}>
            <span style={{ color: '#00ff00', fontSize: '14px' }}>
              ✓ Access Granted
            </span>
          </div>
        </div>

        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '20px',
          marginBottom: '30px'
        }}>
          <div style={{ 
            backgroundColor: '#111',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #333'
          }}>
            <h3 style={{ color: '#00ff00', marginTop: 0 }}>📊 Reports</h3>
            <p style={{ color: '#888', fontSize: '14px' }}>
              Access: <span style={{ color: '#00ff00' }}>Standard User</span>
            </p>
            <p style={{ color: '#666', fontSize: '12px' }}>
              View monthly reports and analytics
            </p>
          </div>

          <div style={{ 
            backgroundColor: '#111',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #333'
          }}>
            <h3 style={{ color: '#00ff00', marginTop: 0 }}>👥 Team</h3>
            <p style={{ color: '#888', fontSize: '14px' }}>
              Members: <span style={{ color: '#00ff00' }}>12 Active</span>
            </p>
            <p style={{ color: '#666', fontSize: '12px' }}>
              Manage team collaboration
            </p>
          </div>

          <div style={{ 
            backgroundColor: '#1a0000',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #660000'
          }}>
            <h3 style={{ color: '#ff6666', marginTop: 0 }}>🔒 Admin Panel</h3>
            <p style={{ color: '#ff6666', fontSize: '14px' }}>
              Access: <span style={{ color: '#ff0000' }}>Denied</span>
            </p>
            <p style={{ color: '#666', fontSize: '12px' }}>
              Requires administrator privileges
            </p>
          </div>
        </div>

        <div style={{ 
          backgroundColor: '#0a0a0a',
          padding: '25px',
          borderRadius: '8px',
          border: '1px solid #222',
          marginBottom: '20px'
        }}>
          <h2 style={{ color: '#00ff00', marginTop: 0 }}>📢 Recent Announcements</h2>
          
          <div style={{ marginBottom: '15px', paddingBottom: '15px', borderBottom: '1px solid #222' }}>
            <p style={{ color: '#00ff00', margin: '0 0 5px 0', fontSize: '14px' }}>
              <strong>System Maintenance</strong> <span style={{ color: '#666', fontSize: '12px' }}>- 2 days ago</span>
            </p>
            <p style={{ color: '#888', margin: 0, fontSize: '13px' }}>
              Scheduled maintenance window on Friday 23:00 - 02:00 UTC
            </p>
          </div>

          <div style={{ marginBottom: '15px', paddingBottom: '15px', borderBottom: '1px solid #222' }}>
            <p style={{ color: '#00ff00', margin: '0 0 5px 0', fontSize: '14px' }}>
              <strong>Security Update</strong> <span style={{ color: '#666', fontSize: '12px' }}>- 1 week ago</span>
            </p>
    
          </div>

          <div>
            <p style={{ color: '#00ff00', margin: '0 0 5px 0', fontSize: '14px' }}>
              <strong>API Documentation Update</strong> <span style={{ color: '#666', fontSize: '12px' }}>- 2 weeks ago</span>
            </p>
            <p style={{ color: '#888', margin: 0, fontSize: '13px' }}>
              Internal API endpoints have been reorganized. Check /api/* for updates.
            </p>
          </div>
        </div>

        <div style={{ 
          backgroundColor: '#001a00',
          padding: '20px',
          borderRadius: '8px',
          border: '1px solid #004400'
        }}>
          <h3 style={{ color: '#00aa00', marginTop: 0 }}>💡 Developer Notes</h3>
          <pre style={{ 
            color: '#00aa00', 
            fontSize: '12px',
            margin: 0,
            fontFamily: 'monospace',
            lineHeight: '1.6'
          }}>
{`// TODO: Review  configuration
 
// Note: Ensure proper authentication headers
// Status: Pending security review`}
          </pre>
        </div>

        <div style={{ 
          marginTop: '30px',
          textAlign: 'center',
          padding: '15px',
          backgroundColor: '#0a0a0a',
          borderRadius: '8px',
          border: '1px dashed #333'
        }}>
          <p style={{ color: '#666', margin: 0, fontSize: '14px' }}>
            🔍 <strong>Next Challenge:</strong> Discover hidden API endpoints to proceed
          </p>
          <p style={{ color: '#444', margin: '10px 0 0 0', fontSize: '11px' }}>
            Hint: /api/s*****
          </p>
        </div>
      </div>
    </div>
  )
}