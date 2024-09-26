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

    <div v-if="showSpeechBubble">
      <img
        src="@/assets/img/simul/speech_bubble_no.png"
        alt="Speech Bubble"
        class="speech-bubble"
      />
      <div class="answer-box">
        <!-- 선택지 버튼 추가 -->
        <div v-if="showChoices" class="choices_2">
          <button
            @mouseover="isHovered = 'yes'"
            @mouseleave="isHovered = ''"
            @click="selectAnswer('yes')"
          >
            <span class="arrow">{{ isHovered === 'yes' ? '▶' : '' }}</span>
            <span class="text">네</span>
          </button>
          <button
            @mouseover="isHovered = 'no'"
            @mouseleave="isHovered = ''"
            @click="selectAnswer('no')"
          >
            <span class="arrow">{{ isHovered === 'no' ? '▶' : '' }}</span>
            <span class="text">아니요</span>
          </button>
        </div>
      </div>
    </div>
    <img
      v-else
      src="@/assets/img/simul/speech_bubble_no.png"
      alt="Speech Bubble No"
      class="speech-bubble"
    />

    <!-- 텍스트 고정 -->
    <div class="main_text_animation">
      <p class="text-line" v-html="typedTextLine1"></p>
      <p
        class="text-line"
        v-html="typedTextLine2"
        v-show="typedTextLine2.length > 0"
      ></p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const fullTextLine1 = '이 도시에서 가장 성공적인';
const fullTextLine2 = '자영업자가 될 준비가 되셨나요?';
const typedTextLine1 = ref('');
const typedTextLine2 = ref('');
const showSpeechBubble = ref(false); // Speech bubble 표시 여부
const showChoices = ref(false); // 선택지 표시 여부
const isHovered = ref(''); // 버튼 호버 상태

const typeText = (text, typedText, delay = 0) => {
  const letters = text.split('');
  let index = 0;

  const interval = setInterval(() => {
    if (index < letters.length) {
      typedText.value += letters[index];
      index++;
    } else {
      clearInterval(interval);
      if (typedText === typedTextLine1) {
        // 첫 번째 줄이 끝난 후 두 번째 줄 애니메이션 시작
        setTimeout(() => {
          typeText(fullTextLine2, typedTextLine2, 500);
        }, 500); // 약간의 딜레이 후 시작
      } else {
        // 두 번째 줄이 끝난 후 speech bubble 표시
        setTimeout(() => {
          showSpeechBubble.value = true; // Speech bubble 표시
          showChoices.value = true; // 선택지 표시
        }, 500);
      }
    }
  }, 100); // 타자 속도 (밀리초)
};

const selectAnswer = (answer) => {
  // 선택지에 대한 응답 처리
  if (answer === 'yes') {
    console.log('네를 선택했습니다.');
    // 네 선택 후 추가 로직
  } else {
    console.log('아니요를 선택했습니다.');
    // 아니요 선택 후 추가 로직
  }
};

onMounted(() => {
  typeText(fullTextLine1, typedTextLine1);
});
</script>

<style scoped>
/* 타자 애니메이션 스타일 */
.main_text_animation {
  position: absolute;
  bottom: 85px; /* Adjust position as needed */
  left: 31%; /* 왼쪽에서 시작하도록 변경 */
  color: #000; /* 텍스트 색상 */
  text-align: left; /* 왼쪽 정렬 */
}

.text-line {
  font-size: 35px; /* 텍스트 크기 */
  font-weight: bold;
  margin: 0; /* 기본 마진 제거 */
  position: absolute; /* 절대 위치 지정 */
  white-space: nowrap; /* 텍스트가 줄바꿈되지 않도록 설정 */
}

.text-line:nth-child(1) {
  bottom: 60px; /* 첫 번째 줄의 위치 */
}

.text-line:nth-child(2) {
  bottom: 0px; /* 두 번째 줄의 위치 (필요에 따라 조정) */
}

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
  transform: translateX(-48%); /* Centering adjustment */
  width: 77%; /* Set the width to 70% */
  opacity: 1;
  transition: opacity 0.5s ease; /* 자연스러운 등장 효과 */
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

/* 선택지 스타일 */
.header-info-choices_2 {
  display: block;
  position: absolute;
  top: 100%;
  left: 0;
  background-color: white;
  border-radius: 20px;
  box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-height: 0;
  overflow: hidden;
  opacity: 0;
  transition: max-height 0.3s ease, opacity 0.3s ease;
}

.choices_2 {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  height: 100%;
  width: 117px;
  margin: 5px 0px 5px 0px;
}

.choices_2 button {
  margin: -5px 0px;
  padding: 10px 20px;
  cursor: pointer;
  display: block;
  font-size: 20px;
  background-color: transparent;
  border-radius: 25px;
  color: black;
  border: none;
  position: relative;
  text-align: left;
}

.choices_2 button span.arrow {
  position: absolute;
  left: 15px; /* 화살표를 버튼 왼쪽에 고정 */
  top: 50%;
  transform: translateY(-50%); /* 세로 가운데 정렬 */
  width: 20px; /* 화살표 크기 고정 */
}

.choices_2 button:hover {
  background-color: #be9788;
  border-radius: 25px;
  font-weight: bold;
}

/* 선택지 텍스트가 밀리지 않도록 고정 */
.choices_2 button span.text {
  padding-left: 15px; /* 화살표를 위한 여백 추가 */
}

.answer-box {
  background-color: #fee9b4;
  position: absolute;
  bottom: 185px; /* Adjust position as needed */
  left: 74%; /* Center horizontally */
  transform: translateX(-50%); /* Centering adjustment */
  width: 200px;
  border-radius: 80px;
  padding: 15px 15px 15px 25px;
}
</style>
