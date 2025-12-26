<h1 id="anonymous-secure-chat-terminal">Anonymous Secure Chat Terminal</h1>
<p>A privacy-centric, end-to-end encrypted (E2EE) chat application architected for absolute anonymity. This platform utilizes a zero-knowledge framework where the server infrastructure remains blind to raw message content, file data, and user private keys.</p>
<p><strong>Live Onion Deployment:</strong> <a href="http://x7dyzsiksqgxnqpp3cuhwi7txq65n3bka5is3wyxceqbbxdkz6ci3uid.onion">http://x7dyzsiksqgxnqpp3cuhwi7txq65n3bka5is3wyxceqbbxdkz6ci3uid.onion</a></p>
<h2 id="authentication-architecture">Authentication Architecture</h2>
<p>In contrast to traditional server-side password storage, this system employs cryptographic signatures for user authentication:</p>
<ul>
<li><strong>Registration:</strong> The client-side application generates a 4096-bit RSA key pair. The Public Key is transmitted to the server for storage, while the Private Key is encrypted via AES-GCM (using the user's local password) and retained exclusively within the user's browser storage or exported as a physical identity file.</li>
<li><strong>Authentication Flow:</strong> The server issues a cryptographically secure random challenge (nonce). The client signs this challenge using their local Private Key and returns the signature. The server validates the signature against the registered Public Key. At no point is a password transmitted to the server.</li>
</ul>
<h3 id="end-to-end-encryption-e2ee">End-to-End Encryption (E2EE)</h3>
<ul>
<li><strong>Messaging:</strong> A hybrid encryption protocol is utilized. For each message, the client generates a transient AES-256 key to encrypt the payload. This symmetric key is then encapsulated using the recipient's RSA Public Key.</li>
<li><strong>Persistence:</strong> To facilitate historical access across sessions, messages are dual-encrypted: once for the intended recipient and once for the sender’s own public key.</li>
<li><strong>File Transfer:</strong> Files are fragmented into encrypted chunks and transmitted via WebSockets. A dedicated AES key is established per transfer, negotiated via RSA, and the integrity is verified post-reassembly using SHA-256 hashing.</li>
</ul>
<h2 id="core-features">Core Features</h2>
<ul>
<li><strong>Anonymity:</strong> No personal identifying information (PII) is required. Identification is based solely on user-defined aliases.</li>
<li><strong>Identity Portability:</strong> Secure export and import functionality for cryptographic identities via encrypted text files.</li>
<li><strong>Real-time Communication:</strong> Low-latency messaging facilitated by Django Channels and asynchronous WebSocket protocols.</li>
<li><strong>Secure File Exchange:</strong> Encrypted binary streaming with granular progress tracking and cryptographic integrity checks.</li>
<li><strong>Data Sovereignty:</strong> Comprehensive administrative controls, including session purging (&ldquo;Nuking&rdquo;) and instant chat history elimination.</li>
<li><strong>Account Termination:</strong> Secure soft-deletion protocols that scrub public keys and associated metadata from the server.</li>
</ul>
<h2 id="technical-specifications">Technical Specifications</h2>
<ul>
<li><strong>Backend Framework:</strong> Django 5.x, Django Channels (ASGI)</li>
<li><strong>Database:</strong> SQLite (default/development), PostgreSQL (recommended for production)</li>
<li><strong>Asynchronous Server:</strong> Daphne</li>
<li><strong>Cryptography:</strong>
<ul>
<li><strong>Backend:</strong> <code>cryptography</code> (Python) for signature verification and server-side logic.</li>
<li><strong>Frontend:</strong> <code>Web Crypto API</code> (Native Browser) for all RSA/AES cryptographic operations.</li>
</ul>
</li>
<li><strong>Networking:</strong> WebSockets for bidirectional messaging and binary data relay.</li>
</ul>
<h2 id="installation-and-deployment">Installation and Deployment</h2>
<h3 id="repository-acquisition">1. Repository Acquisition</h3>
<pre><code class="language-bash">git clone [https://github.com/dkydivyansh/Onion-chat-room.git](https://github.com/dkydivyansh/Onion-chat-room.git)
cd Onion-chat-room
</code></pre>
<h3 id="environment-configuration">2. Environment Configuration</h3>
<p>Establish a virtual environment and install the required dependencies:</p>
<pre><code class="language-bash">python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
</code></pre>
<h3 id="database-initialisation">3. Database Initialisation</h3>
<p>Execute the following commands to configure the database schema and apply migrations:</p>
<pre><code class="language-bash">python manage.py makemigrations chat
python manage.py migrate
</code></pre>
<h3 id="administrative-configuration-optional">4. Administrative Configuration (Optional)</h3>
<p>To initialize access to the Django administrative interface for manual moderation or room management:</p>
<pre><code class="language-bash">python manage.py createsuperuser
</code></pre>
<h3 id="application-execution">5. Application Execution</h3>
<p>The application requires an ASGI-compliant server environment to handle WebSocket connections:</p>
<pre><code class="language-bash">python manage.py runserver
</code></pre>
<p>The terminal interface will be available at <code>http://127.0.0.1:8000</code>.</p>
<h2 id="project-structure">Project Structure</h2>
<ul>
<li><code>models.py</code>: Defines the relational schema for <code>AnonymousUser</code>, <code>ChatRoom</code>, and <code>Message</code> (storing only encrypted payloads).</li>
<li><code>consumers.py</code>: Manages asynchronous WebSocket logic and binary chunk relay.</li>
<li><code>views.py</code>: Controls the REST API endpoints and the cryptographic challenge-response authentication logic.</li>
<li><code>templates/</code>: Contains the terminal-styled user interface for the dashboard and chat environments.</li>
</ul>
<p><strong>Disclaimer:</strong> This software is provided for educational and privacy-research purposes. Users are responsible for maintaining the security of their local environment and cryptographic private keys.</p>
