pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './mvnw package -B -Dbuildnum=${BUILD_NUMBER}'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: 'target/Sonatype**.jar')
      }
    }
  }
}