pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'vulnerable-flask-app'
        CONTAINER_NAME = 'flask-audit-test'
        // Definimos la IP objetivo para que sea fácil de leer
        TARGET_IP = '10.0.0.183'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Construcción (Build)') {
            steps {
                script {
                    echo '--- Construyendo Imagen Docker ---'
                    sh "docker build -t ${DOCKER_IMAGE}:${BUILD_NUMBER} ."
                }
            }
        }

        stage('Análisis Estático (SAST) - Bandit') {
            steps {
                script {
                    echo '--- Ejecutando Bandit ---'
                    // || true permite que el pipeline siga aunque encuentre fallos
                    sh """
                    docker run --rm -v \$(pwd):/src python:3.9-slim bash -c "pip install bandit && bandit -r /src/vulnerable_flask_app.py -f html -o /src/bandit_report.html || true"
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'bandit_report.html', allowEmptyArchive: true
                }
            }
        }

        stage('Despliegue para Pruebas') {
            steps {
                script {
                    echo '--- Levantando Contenedor ---'
                    sh "docker rm -f ${CONTAINER_NAME} || true"
                    // Mapeamos puerto 5000
                    sh "docker run -d -p 5000:5000 --name ${CONTAINER_NAME} ${DOCKER_IMAGE}:${BUILD_NUMBER}"
                    echo "Esperando a que Flask inicie..."
                    sh "sleep 10" 
                }
            }
        }

        stage('Análisis Dinámico (DAST) - OWASP ZAP') {
            steps {
                script {
                    echo "--- Ejecutando OWASP ZAP contra ${TARGET_IP} ---"
                    
                    // 1. Truco de permisos: Creamos el archivo antes para que ZAP pueda escribirlo
                    sh 'touch zap_report.html && chmod 777 zap_report.html'
                    
                    // 2. Ejecución: Usamos la IP de la VM (10.0.0.183)
                    sh """
                    docker run --rm --network host -v \$(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py \
                    -t http://${TARGET_IP}:5000 \
                    -r zap_report.html \
                    || true
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap_report.html', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            echo '--- Limpieza ---'
            sh "docker rm -f ${CONTAINER_NAME} || true"
        }
    }
}