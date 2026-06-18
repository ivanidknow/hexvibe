// Vulnerable: GO-119
- |
                print("hi")
                print("{{inputs.parameters.message}}")
            resources: {}
    - name: print-message-secure
      inputs:
        parameters:
          - name: message
      script:
        image: debian:9.4
...
          value: "{{inputs.parameters.message}}"
        command: [bash]
