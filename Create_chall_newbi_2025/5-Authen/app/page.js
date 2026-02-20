export default function Home() {
  return (
    <div style={{ maxWidth: '800px', margin: '50px auto', padding: '20px' }}>
      <div style={{ 
        border: '2px solid #00ff00', 
        borderRadius: '10px', 
        padding: '30px',
        backgroundColor: '#0a0a0a',
        boxShadow: '0 0 20px rgba(0, 255, 0, 0.3)'
      }}>
        <h1 style={{ 
          textAlign: 'center', 
          color: '#00ff00',
          marginBottom: '10px',
          fontSize: '32px'
        }}>
          🔐 Không thể đăng nhập
        </h1>
        <p style={{ 
          textAlign: 'center', 
          color: '#666',
          marginBottom: '30px',
          fontSize: '14px'
        }}>
   
        </p>

        <div style={{ 
          backgroundColor: '#111', 
          padding: '30px', 
          borderRadius: '8px',
          border: '1px solid #333'
        }}>
          <h2 style={{ color: '#00ff00', marginBottom: '20px' }}></h2>
          
          <form style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '5px', color: '#888' }}>
                Username
              </label>
              <input 
                type="text" 
                placeholder="Enter your username"
                style={{ 
                  width: '100%', 
                  padding: '10px',
                  backgroundColor: '#1a1a1a',
                  border: '1px solid #333',
                  borderRadius: '5px',
                  color: '#00ff00',
                  fontFamily: 'monospace'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '5px', color: '#888' }}>
                Password
              </label>
              <input 
                type="password" 
                placeholder="Enter your password"
                style={{ 
                  width: '100%', 
                  padding: '10px',
                  backgroundColor: '#1a1a1a',
                  border: '1px solid #333',
                  borderRadius: '5px',
                  color: '#00ff00',
                  fontFamily: 'monospace'
                }}
              />
            </div>

            <button 
              type="button"
              style={{ 
                padding: '12px',
                backgroundColor: '#003300',
                border: '2px solid #00ff00',
                borderRadius: '5px',
                color: '#00ff00',
                fontFamily: 'monospace',
                fontSize: '16px',
                cursor: 'not-allowed',
                marginTop: '10px'
              }}
            >
              Login (Disabled)
            </button>
          </form>

          <div style={{ 
            marginTop: '20px', 
            padding: '15px',
            backgroundColor: '#1a0000',
            border: '1px solid #ff0000',
            borderRadius: '5px'
          }}>
        
            <p style={{ color: '#666', margin: '5px 0 0 0', fontSize: '12px' }}>
              The login system is currently under maintenance. Please contact IT support.
            </p>
          </div>
        </div>

        <div style={{ 
          marginTop: '30px',
          padding: '20px',
          backgroundColor: '#0a0a0a',
          border: '1px solid #222',
          borderRadius: '8px'
        }}>
    
         
        </div>

        <div style={{ 
          marginTop: '20px',
          padding: '15px',
          backgroundColor: '#001a00',
          border: '1px solid #004400',
          borderRadius: '8px'
        }}>
      
        </div>

        <p style={{ 
          textAlign: 'center', 
          color: '#333', 
          marginTop: '30px',
          fontSize: '12px'
        }}>
          © 2025 NextCorp Industries | All Rights Reserved
        </p>
      </div>
    </div>
  )
}