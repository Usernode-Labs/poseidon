FROM sagemath/sagemath:latest

# Set working directory
WORKDIR /home/sage

# Copy the parameter generation script
COPY generate_params_poseidon.sage .

# Create a script to run all configurations
RUN echo '#!/bin/bash' > run_poseidon_params.sh && \
    echo 'echo "Generating Poseidon parameters for Pallas curve..."' >> run_poseidon_params.sh && \
    echo 'echo "Prime modulus: 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001"' >> run_poseidon_params.sh && \
    echo 'echo ""' >> run_poseidon_params.sh && \
    echo '' >> run_poseidon_params.sh && \
    echo 'echo "Configuration 1: t=3, alpha=5"' >> run_poseidon_params.sh && \
    echo 'sage generate_params_poseidon.sage 1 0 255 3 5 128 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001' >> run_poseidon_params.sh && \
    echo 'echo ""' >> run_poseidon_params.sh && \
    echo '' >> run_poseidon_params.sh && \
    echo 'echo "Configuration 2: t=5, alpha=5"' >> run_poseidon_params.sh && \
    echo 'sage generate_params_poseidon.sage 1 0 255 5 5 128 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001' >> run_poseidon_params.sh && \
    echo 'echo ""' >> run_poseidon_params.sh && \
    echo '' >> run_poseidon_params.sh && \
    echo 'echo "Configuration 3: t=9, alpha=5"' >> run_poseidon_params.sh && \
    echo 'sage generate_params_poseidon.sage 1 0 255 9 5 128 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001' >> run_poseidon_params.sh && \
    echo 'echo ""' >> run_poseidon_params.sh && \
    echo '' >> run_poseidon_params.sh && \
    echo 'echo "Configuration 4: t=3, alpha=3"' >> run_poseidon_params.sh && \
    echo 'sage generate_params_poseidon.sage 1 0 255 3 3 128 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001' >> run_poseidon_params.sh && \
    echo 'echo ""' >> run_poseidon_params.sh && \
    echo 'echo "All parameter files generated!"' >> run_poseidon_params.sh && \
    echo 'ls -la *.txt' >> run_poseidon_params.sh && \
    chmod +x run_poseidon_params.sh

# Default command
CMD ["./run_poseidon_params.sh"]