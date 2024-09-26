<template>
  <div class="animation-container">
    <img
      src="@/assets/img/simul/sumul_cut.jpg"
      alt="Background Image"
      class="background-image"
    />
    <img
      src="@/assets/img/simul/leaf1.png"
      alt="Leaf"
      class="leaf-animation1"
    />
    <img
      src="@/assets/img/simul/leaf2.png"
      alt="Leaf"
      class="leaf-animation2"
    />
    <img
      src="@/assets/img/simul/leaf3.png"
      alt="Leaf"
      class="leaf-animation3"
    />
    <img
      src="@/assets/img/simul/leaf4.png"
      alt="Leaf"
      class="leaf-animation4"
    />
    <img
    src="@/assets/img/simul/leaf1.png"
    alt="Leaf"
    class="leaf-animation5"
  />
  <img
      src="@/assets/img/simul/speech_bubble.png"
      alt="Speech Bubble"
      class="speech-bubble"
    />
  </div>
</template>

<script setup>
</script>

<style scoped>
.animation-container {
  position: relative;
  width: 100%;
  height: 712px;
  overflow: hidden;
}

.background-image {
  width: 100%;
  height: 100%;
  object-fit: cover;
}


.speech-bubble {
  position: absolute;
  bottom: 5px; /* Adjust the distance from the bottom */
  left: 50%; /* Center horizontally */
  transform: translateX(-45%); /* Centering adjustment */
  width: 60%; /* Set the width to 70% */
  /* Add additional styling if needed */

}

.leaf-animation1,
.leaf-animation2,
.leaf-animation3,
.leaf-animation4,
.leaf-animation5 {
  position: absolute;
  top: -100px;
  width: 50px; /* Adjust the size of the leaf */
  animation: leaf-fall linear infinite;
}

/* Add different initial positions, animation durations, and delays */
.leaf-animation1 {
  left: 10%;
  animation-duration: 8s;
  animation-delay: 0s;
}

.leaf-animation2 {
  left: 25%;
  animation-duration: 17s;
  animation-delay: 0.5s;
}

.leaf-animation3 {
  left: 80%;
  animation-duration: 10s;
  animation-delay: 2s;
}

.leaf-animation4 {
  left: 70%;
  animation-duration: 8s;
  animation-delay: 1s;
}
.leaf-animation5 {
  left: 90%;
  animation-duration: 17s;
  animation-delay: 0.5s;
}

@keyframes leaf-fall {
  0% {
    transform: translate(-50%, 0) rotate(0deg);
    opacity: 1;
  }
  100% {
    transform: translate(-50%, 800px) rotate(360deg);
    opacity: 1;
  }
}


</style>
