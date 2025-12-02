pipeline {
    agent any

    environment {
        // Nombre de la imagen y contenedor para este proyecto
        DOCKER_IMAGE = 'vulnerable-flask-app'
        CONTAINER_NAME = 'flask-audit-test'
    }

    stages {
        stage('Checkout') {
            steps {
                // Descarga el código del repositorio Git
                checkout scm
            }
        }

        stage('Construcción (Build)') {
            steps {
                script {
                    echo '--- Construyendo Imagen Docker ---'
                    // Construye la imagen usando el número de ejecución de Jenkins como tag
                    sh "docker build -t ${DOCKER_IMAGE}:${BUILD_NUMBER} ."
                }
            }
        }

        stage('Análisis Estático (SAST) - Bandit') {
            steps {
                script {
                    echo '--- Ejecutando Bandit ---'
                    // Usamos un contenedor temporal de Python para correr Bandit sin instalar nada en el servidor
                    // El "|| true" evita que el pipeline se detenga si encuentra fallos (queremos ver el reporte)
                    sh """
                    docker run --rm -v \$(pwd):/src python:3.9-slim bash -c "pip install bandit && bandit -r /src/vulnerable_flask_app.py -f html -o /src/bandit_report.html || true"
                    """
                }
            }
            post {
                always {
                    // Guarda el reporte HTML en Jenkins
                    archiveArtifacts artifacts: 'bandit_report.html', allowEmptyArchive: true
                }
            }
        }

        stage('Despliegue para Pruebas') {
            steps {
                script {
                    echo '--- Levantando Contenedor ---'
                    // Limpieza previa por si quedó algo corriendo
                    sh "docker rm -f ${CONTAINER_NAME} || true"
                    // Corremos la app en segundo plano (-d) en el puerto 5000
                    sh "docker run -d -p 5000:5000 --name ${CONTAINER_NAME} ${DOCKER_IMAGE}:${BUILD_NUMBER}"
                    // Esperamos 5 segundos para asegurar que la DB y Flask arranquen
                    sh "sleep 5"
                }
            }
        }

        stage('Análisis Dinámico (DAST) - OWASP ZAP') {
            steps {
                script {
                    echo '--- Ejecutando OWASP ZAP ---'
                    // Usamos --network host para que ZAP pueda ver 'localhost:5000' de la máquina virtual
                    // zap-baseline.py es ideal para escaneos rápidos
                    sh """
                    touch zap_report.html && chmod 777 zap_report.html
                    docker run --rm --network host -v \$(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py \
                    -t http://10.0.0.183:5000 \
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
            // Apagamos el contenedor de pruebas al finalizar
            sh "docker rm -f ${CONTAINER_NAME} || true"
        }
    }
}
