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
        <!-- 각 버튼을 감싸는 div에 v-for 추가 -->
        <div v-if="showChoices" class="choices_2">
          <div v-for="(choice, index) in choices" :key="index">
            <button
              @mouseover="isHovered = choice.text"
              @mouseleave="isHovered = ''"
              @click="selectAnswer(choice.value)"
            >
              <span class="arrow">{{
                isHovered === choice.text ? '▶' : ''
              }}</span>
              <span class="text">{{ choice.text }}</span>
            </button>
          </div>
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

const fullTexts = [
  {
    line1: '이 도시에서 가장 성공적인',
    line2: '자영업자가 될 준비가 되셨나요?',
  },
  {
    line1: '다음 단계로 나아가고 싶으신가요?',
    line2: '더 많은 정보를 원하십니까?',
  },
];

const choices = [
  { text: '네', value: 'yes' },
  { text: '아니요', value: 'no' },
  { text: '더 알아보기', value: 'more_info' },
];

const typedTextLine1 = ref('');
const typedTextLine2 = ref('');
const showSpeechBubble = ref(false);
const showChoices = ref(false);
const isHovered = ref('');

const typeText = (text, typedText, nextText, delay = 0) => {
  const letters = text.split('');
  let index = 0;

  const interval = setInterval(() => {
    if (index < letters.length) {
      typedText.value += letters[index];
      index++;
    } else {
      clearInterval(interval);
      if (nextText) {
        setTimeout(() => {
          typeText(nextText, typedText === typedTextLine1 ? typedTextLine2 : null);
        }, 500);
      } else {
        setTimeout(() => {
          showSpeechBubble.value = true;
          showChoices.value = true;
        }, 500);
      }
    }
  }, 100);
};

const selectAnswer = (answer) => {
  console.log(`선택한 응답: ${answer}`);
  // 선택한 응답에 따른 추가 로직 구현
};

onMounted(() => {
  typeText(fullTexts[0].line1, typedTextLine1, fullTexts[0].line2);
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
  margin: 5px 0px 5px 0px;
}

.choices_2 div {
  margin-bottom: -5px; /* 버튼 간 간격을 줄이기 */
}

.choices_2 button {
  padding: 10px 15px; /* 수직 패딩과 수평 패딩 설정 */
  cursor: pointer;
  display: flex; /* 플렉스 박스를 사용하여 정렬 */
  align-items: center; /* 세로 중앙 정렬 */
  font-size: 20px; /* 폰트 크기 */
  background-color: transparent; /* 기본 배경 색상 */
  border-radius: 25px; /* 둥근 모서리 */
  color: black; /* 텍스트 색상 */
  border: none; /* 테두리 없음 */
  text-align: left; /* 텍스트 왼쪽 정렬 */
  transition: background-color 0.3s ease; /* 배경 색상 전환 효과 */
}

.choices_2 button span.arrow {
  width: 20px; /* 화살표 크기 고정 */
  font-size: 14px;
}

.choices_2 button:hover {
  background-color: #fcd752; /* 호버 시 배경 색상 */
  border-radius: 25px;
  font-weight: bold;
  padding: 10px 20px; /* 여백을 다시 설정하여 안정성 확보 */
}

/* 선택지 텍스트가 밀리지 않도록 고정 */
.choices_2 button span.text {
  padding-left: 5px; /* 화살표를 위한 여백 추가 */
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
