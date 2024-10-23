# dnsserver-nabil

A simple and efficient DNS server implemented in Rust, designed to handle DNS queries and responses. This project includes documentation and tests to ensure functionality and reliability.

## Features

- **DNS Query Handling**: Supports various DNS query types, including A, AAAA, MX, NS, and CNAME.
- **Custom Implementation**: Fully implemented from scratch with a focus on clarity and maintainability.
- **Documentation**: Inline documentation explaining the code structure and logic.
- **Tests**: Comprehensive test suite covering all aspects of the DNS server functionality.

## Getting Started

### Prerequisites

- Rust and Cargo installed on your machine. You can install Rust using [rustup](https://rustup.rs/).

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/codescalersinternships/dnsserver-nabil/tree/development
   ```

2. Navigate to the project directory:

   ```bash
   cd dnsserver-nabil
   ```

3. Build the project:

   ```bash
   cargo build
   ```

### Running the Server

To run the DNS server, use the following command:

```bash
make run
```

### Running Tests

To ensure everything is working correctly, you can run the test suite with:

```bash
make test
```



## Usage

Once the server is running, you can send DNS queries using any DNS client or command-line tools like `dig` or `nslookup`. For example:

```bash
dig @localhost -p 2053 example.com
```

## Documentation

This project is thoroughly documented. You can find detailed explanations of the code and its functionality within the source files. Additionally, you can generate and view the documentation using:

```bash
make doc
```

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.

